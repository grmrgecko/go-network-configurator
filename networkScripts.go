package netconfig

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"dario.cat/mergo"
	"github.com/vishvananda/netlink"
)

const networkScriptsPath = "/etc/sysconfig/network-scripts"

type nsFile struct {
	Name   string
	Config map[string]string
}

type nsRouteFile struct {
	Name   string
	Routes [][]string
}
type nsInterface struct {
	Name       string
	IFFiles    []nsFile
	Route4File nsRouteFile
	Route6File nsRouteFile
}

type networkScripts struct {
	Interfaces      []*nsInterface
	ConfigDir       string
	backupRetention int
}

// Either retreives an existing interface, or makes a new one.
func (ns *networkScripts) EnsureInterface(name string) *nsInterface {
	// Find existing interface and return it.
	for _, iface := range ns.Interfaces {
		if iface.Name == name {
			return iface
		}
	}

	// Make a new interface as one wasn't found.
	iface := &nsInterface{
		Name: name,
	}
	ns.Interfaces = append(ns.Interfaces, iface)
	return iface
}

// Parse a file that should only contain key=value data.
func parseKeyValueFile(fd *os.File) (map[string]string, error) {
	// Setup the response.
	resp := make(map[string]string)

	var builder strings.Builder
	readKey := false
	inSingleQuote := false
	inDoubleQuote := false
	var key string
	var value string

	scanner := bufio.NewScanner(fd)
lineLoop:
	for scanner.Scan() {
		line := scanner.Bytes()

		// Trim whitespace.
		line = bytes.TrimFunc(line, unicode.IsSpace)

		// Ignore blank lines.
		if len(line) == 0 {
			continue
		}

		// Ignore comments.
		if line[0] == '#' {
			continue
		}

		lineLen := len(line)
	readLoop:
		for i := 0; i < lineLen; i++ {
			b := line[i]
			// Handle single quotes.
			if b == '\'' && !inDoubleQuote {
				if inSingleQuote {
					inSingleQuote = false
				} else {
					inSingleQuote = true
				}
				continue
			}

			// Handle double quotes.
			if b == '"' && !inSingleQuote {
				if inDoubleQuote {
					inDoubleQuote = false
				} else {
					inDoubleQuote = true
				}
				continue
			}

			// Handle escapes.
			if b == '\\' {
				if i+1 >= lineLen {
					continue lineLoop
				}
				if inDoubleQuote && line[i+1] == '"' {
					i++
					builder.WriteByte('"')
					continue
				}
			}

			// If equal sign and not in a quote, handle key logic.
			if b == '=' && !inDoubleQuote && !inSingleQuote {
				if readKey {
					return nil, fmt.Errorf("invalid file syntax in %s", fd.Name())
				}
				key = builder.String()
				builder.Reset()
				readKey = true
				continue
			}

			// Handle spaces outside of quotes.
			if unicode.IsSpace(rune(b)) && !inDoubleQuote && !inSingleQuote {
				// If there is an space outside of an quote,
				// and its not leading to an comment or
				// the end of line, it is invalid.
				for ; i < lineLen; i++ {
					b := line[i]
					if unicode.IsSpace(rune(b)) {
						continue
					} else if b == '#' {
						break readLoop
					} else {
						return nil, fmt.Errorf("invalid file syntax in %s", fd.Name())
					}
				}
				break
			}

			// Write data.
			builder.WriteByte(b)
		}

		// If we ended reading line in a quote, continue to next line.
		if inDoubleQuote || inSingleQuote {
			continue lineLoop
		}

		// If we didn't read a key, that's invalid.
		if !readKey {
			return nil, fmt.Errorf("invalid file syntax in %s", fd.Name())
		}

		// At this point, we have fully read the key/value.
		value = builder.String()
		builder.Reset()
		readKey = false

		// Assign key/value.
		resp[key] = value
	}
	return resp, nil
}

// Read list of IP route formatted fields and return list of routes.
func parseIPRoutes(routes [][]string) (resp []*Route) {
	// Loop through each route.
routeLoop:
	for _, route := range routes {
		// If the length of fields is 0, no route to parse.
		routeLen := len(route)
		if routeLen == 0 {
			continue
		}

		// Try and parse the network field.
		ip, network, err := net.ParseCIDR(route[0])
		if err != nil {
			continue
		}
		network.IP = ip

		// Read the fields.
		var gateway net.IP
		metric := int(256)
		for i := 1; i < routeLen; i++ {
			field := route[i]
			if field == "via" && i+1 < routeLen {
				i++
				gateway = net.ParseIP(route[i])
				if gateway == nil {
					continue routeLoop
				}
			}
			if field == "metric" && i+1 < routeLen {
				i++
				metric, err = strconv.Atoi(route[i])
				if err != nil || metric == 0 {
					metric = 256
				}
			}
		}

		// Add the route.
		r := new(Route)
		r.Destination = network
		r.Gateway = gateway
		r.Metric = metric
		resp = append(resp, r)
	}
	return
}

func newNetworkScripts(backupRetention int) (ns *networkScripts, err error) {
	ns, err = newNetworkScriptsWithConfig(networkScriptsPath)
	if ns != nil {
		ns.backupRetention = backupRetention
	}
	return
}

func newNetworkScriptsWithConfig(configPath string) (ns *networkScripts, err error) {
	// Try to read the directory files.
	unsortedEntries, err := os.ReadDir(configPath)
	if err != nil {
		return
	}

	// Sort by name.
	entries := sortableDirEntries(unsortedEntries)
	sort.Sort(entries)

	// Setup response.
	ns = new(networkScripts)
	ns.ConfigDir = configPath

	// Setup regex match for route network/netmask style.
	routeRe := regexp.MustCompile(`^\s*ADDRESS[0-9]+=`)

	for _, entry := range entries {
		// If not an network file, skip.
		if entry.IsDir() {
			continue
		}

		// If the file is a interface config file, read it.
		if strings.HasPrefix(entry.Name(), "ifcfg-") {
			// Open the file.
			configFile := path.Join(configPath, entry.Name())
			fd, err := os.Open(configFile)
			if err != nil {
				return nil, err
			}

			// Parse the file.
			resp, err := parseKeyValueFile(fd)
			fd.Close()
			if err != nil {
				return nil, err
			}

			// Find the device name.
			devName, ok := resp["DEVICE"]
			if !ok || devName == "" {
				devName = entry.Name()[6:]
			}
			idx := strings.IndexByte(devName, ':')
			if idx != -1 {
				devName = devName[:idx]
			}

			// In the rare event the device name isn't found with the above,
			// try hardware address matching.
			if devName == "" {
				hwAddr, ok := resp["HWADDR"]
				mac, err := net.ParseMAC(hwAddr)
				if !ok || err != nil {
					return nil, fmt.Errorf("unable to find interface name in %s", configFile)
				}
				ifaces, err := net.Interfaces()
				if err != nil {
					return nil, err
				}
				for _, iface := range ifaces {
					if bytes.Equal(iface.HardwareAddr, mac) {
						devName = iface.Name
						break
					}
				}
				if devName == "" {
					return nil, fmt.Errorf("unable to find interface name in %s", configFile)
				}
			}

			// Setup file.
			file := nsFile{
				Name:   entry.Name(),
				Config: resp,
			}

			// Get the interface.
			iface := ns.EnsureInterface(devName)

			// Add the file to the config.
			iface.IFFiles = append(iface.IFFiles, file)
		}

		// If the file is a route file.
		if strings.HasPrefix(entry.Name(), "route-") {
			// Get the device name for the network/netmask format.
			devName := entry.Name()[6:]
			if devName == "" {
				return nil, fmt.Errorf("invalid route file name")
			}

			// Open the file.
			configFile := path.Join(configPath, entry.Name())
			fd, err := os.Open(configFile)
			if err != nil {
				return nil, err
			}

			// Confirm file type.
			file := nsRouteFile{
				Name: entry.Name(),
			}
			isNetworkMas := false
			scanner := bufio.NewScanner(fd)
			for scanner.Scan() {
				line := scanner.Text()
				if routeRe.MatchString(line) {
					isNetworkMas = true
					break
				}
			}
			fd.Seek(0, io.SeekStart)

			// Parse depending on type.
			if isNetworkMas {
				// Parse key value file.
				resp, err := parseKeyValueFile(fd)
				fd.Close()
				if err != nil {
					return nil, err
				}

				// Parse network/netmask configuration.
				for i := 0; ; i++ {
					var route []string
					addr, ok := resp[fmt.Sprintf("ADDRESS%d", i)]
					if !ok {
						break
					}
					netmask, ok := resp[fmt.Sprintf("NETMASK%d", i)]
					if !ok {
						return nil, fmt.Errorf("invalid file format, missing netmask %s", configFile)
					}
					gateway, ok := resp[fmt.Sprintf("GATEWAY%d", i)]
					if !ok {
						return nil, fmt.Errorf("invalid file format, missing gateway %s", configFile)
					}
					ipMask := net.ParseIP(netmask).To4()
					if ipMask == nil {
						return nil, fmt.Errorf("invalid file format %s", configFile)
					}
					mask := net.IPMask(ipMask)
					prefix, _ := mask.Size()
					route = append(route, fmt.Sprintf("%s/%d", addr, prefix), "via", gateway, "dev", devName)
					file.Routes = append(file.Routes, route)
				}
			} else {
				// Read ip command format routes.
				scanner := bufio.NewScanner(fd)
				for scanner.Scan() {
					line := scanner.Text()
					line = strings.TrimSpace(line)

					// Ignore blank lines and comments.
					if line == "" || line[0] == '#' {
						continue
					}

					// Parse route.
					route := strings.Fields(line)
					file.Routes = append(file.Routes, route)
				}
				fd.Close()
			}

			// Get the interface.
			iface := ns.EnsureInterface(devName)

			// Add the route to the iface.
			iface.Route4File = file
		}

		// If the file is a route file.
		if strings.HasPrefix(entry.Name(), "route6-") {
			// Get the device name for use in assigning to interface.
			devName := entry.Name()[7:]
			if devName == "" {
				return nil, fmt.Errorf("invalid route file name")
			}

			// Open the file.
			configFile := path.Join(configPath, entry.Name())
			fd, err := os.Open(configFile)
			if err != nil {
				return nil, err
			}

			// Read ip command format routes.
			file := nsRouteFile{
				Name: entry.Name(),
			}
			scanner := bufio.NewScanner(fd)
			for scanner.Scan() {
				line := scanner.Text()
				line = strings.TrimSpace(line)

				// Ignore blank lines and comments.
				if line == "" || line[0] == '#' {
					continue
				}

				// Parse route.
				route := strings.Fields(line)
				file.Routes = append(file.Routes, route)
			}
			fd.Close()

			// Get the interface.
			iface := ns.EnsureInterface(devName)

			// Add the route to the iface.
			iface.Route6File = file
		}
	}
	return
}

// Reads the environment variables at an IP index, and returns an ipnet.
func (ns *networkScripts) ParseIP(cfg map[string]string, idx string) *net.IPNet {
	// Get the IPADDR environment, non-existing means no IP.
	addr, ok := cfg["IPADDR"+idx]
	if !ok || addr == "" {
		return nil
	}

	// Get the prefix and netmask to get network size.
	prefix := cfg["PREFIX"+idx]
	netmask := cfg["NETMASK"+idx]

	// If the prefix isn't found, try parsing it from the netmask.
	if prefix == "" {
		// Get the prefix from netmask, defaulting to 16.
		ipMask := net.ParseIP(netmask).To4()
		if ipMask != nil {
			mask := net.IPMask(ipMask)
			ones, _ := mask.Size()
			prefix = strconv.Itoa(ones)
		} else {
			prefix = "16"
		}
	}

	// Parse the CIDR.
	ip, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%s", addr, prefix))
	if err != nil {
		return nil
	}
	ipnet.IP = ip
	return ipnet
}

// Get interfaces configured.
func (ns *networkScripts) GetInterfaces() (interfaces []*Interface, err error) {
	// Connect to netlink.
	var h *netlink.Handle
	h, err = netlink.NewHandle()
	if err != nil {
		return
	}
	defer h.Close()

	// Get list of interfaces to match with MAC address.
	var links []netlink.Link
	links, err = h.LinkList()
	if err != nil {
		return
	}

	for _, iface := range ns.Interfaces {
		i := new(Interface)
		i.Name = iface.Name

		// Discover the interface name and mac address.
		for _, link := range links {
			if link.Attrs().Name == iface.Name {
				i.MAC = link.Attrs().HardwareAddr
				i.Link = link
			}
		}

		// Parse interface files.
		for _, file := range iface.IFFiles {
			// Parse IPv4 addresses in the file.
			ipAddr := ns.ParseIP(file.Config, "")
			if ipAddr != nil {
				i.Addresses = append(i.Addresses, ipAddr)
			}
			for idx := 0; idx <= 255; idx++ {
				ipAddr = ns.ParseIP(file.Config, strconv.Itoa(idx))
				if ipAddr != nil {
					i.Addresses = append(i.Addresses, ipAddr)
				} else if idx >= 2 {
					break
				}
			}
			gateway4 := file.Config["GATEWAY"]
			if gateway4 != "" {
				i.Gateway4 = net.ParseIP(gateway4)
			}
			gateway6 := file.Config["IPV6_DEFAULTGW"]
			if gateway6 != "" {
				i.Gateway6 = net.ParseIP(gateway6)
			}

			// Parse DNS servers (DNS1, DNS2, ...) and search domains.
			for idx := 1; ; idx++ {
				dns, ok := file.Config[fmt.Sprintf("DNS%d", idx)]
				if !ok {
					break
				}
				if ip := net.ParseIP(dns); ip != nil {
					i.DNS = append(i.DNS, ip)
				}
			}
			if domain := file.Config["DOMAIN"]; domain != "" {
				i.SearchDomains = append(i.SearchDomains, strings.Fields(domain)...)
			}

			// Parse IPv6 addresses in the file.
			addr := file.Config["IPV6ADDR"]
			if addr != "" {
				ip, ipnet, err := net.ParseCIDR(addr)
				if err == nil {
					ipnet.IP = ip
					i.Addresses = append(i.Addresses, ipnet)
				}
			}
			addrs := strings.Fields(file.Config["IPV6ADDR_SECONDARIES"])
			for _, addr := range addrs {
				ip, ipnet, err := net.ParseCIDR(addr)
				if err == nil {
					ipnet.IP = ip
					i.Addresses = append(i.Addresses, ipnet)
				}
			}
		}

		// Parse static routes.
		i.Routes = parseIPRoutes(iface.Route4File.Routes)
		route6 := parseIPRoutes(iface.Route6File.Routes)
		i.Routes = append(i.Routes, route6...)

		// Add interface.
		interfaces = append(interfaces, i)
	}
	return
}

// Save an interface to script.
func (n *nsInterface) Save(config map[string]string, configDir string, backupRetention int) error {
	// Get config paths.
	configName := fmt.Sprintf("ifcfg-%s", n.Name)
	configPath := path.Join(configDir, configName)
	tmpName := fmt.Sprintf(".tmp.%d.%s", time.Now().UnixNano(), configName)
	tmpPath := path.Join(configDir, tmpName)

	// Try to encode/save the config.
	fd, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	var keys []string
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := config[key]
		if strings.ContainsFunc(val, unicode.IsSpace) {
			fmt.Fprintf(fd, "%s=\"%s\"\n", key, val)
		} else {
			fmt.Fprintf(fd, "%s=%s\n", key, val)
		}
	}
	fd.Close()

	// Backup existing configs.
	prefix := fmt.Sprintf(".bak.%d.", time.Now().UnixNano())
	for _, file := range n.IFFiles {
		newName := prefix + file.Name
		oldFile := path.Join(configDir, file.Name)
		newFile := path.Join(configDir, newName)
		err := fileMove(oldFile, newFile)
		if err != nil {
			return err
		}
	}

	// Move new config in place.
	err = fileMove(tmpPath, configPath)
	if err != nil {
		return err
	}

	// Update the config in the structure.
	n.IFFiles = []nsFile{{
		Name:   configName,
		Config: config,
	}}

	// Prune old backups beyond the retention count.
	for _, file := range n.IFFiles {
		pruneBackups(configDir, prefixBackupMatcher(file.Name), backupRetention)
	}

	return nil
}

// Save an interface to script.
func (n *nsInterface) SaveRouteFiles(routes4 []string, routes6 []string, configDir string, backupRetention int) error {
	// Get config paths for routes IPv4.
	config4Name := fmt.Sprintf("route-%s", n.Name)
	config4Path := path.Join(configDir, config4Name)
	tmp4Name := fmt.Sprintf(".tmp.%d.%s", time.Now().UnixNano(), config4Name)
	tmp4Path := path.Join(configDir, tmp4Name)

	// Try to encode/save the config.
	if len(routes4) != 0 {
		fd, err := os.OpenFile(tmp4Path, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		for _, route := range routes4 {
			fmt.Fprintln(fd, route)
		}
		fd.Close()
	}

	// Get config paths for routes IPv6
	config6Name := fmt.Sprintf("route6-%s", n.Name)
	config6Path := path.Join(configDir, config6Name)
	tmp6Name := fmt.Sprintf(".tmp.%d.%s", time.Now().UnixNano(), config6Name)
	tmp6Path := path.Join(configDir, tmp6Name)

	// Try to encode/save the config.
	if len(routes6) != 0 {
		fd, err := os.OpenFile(tmp6Path, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		for _, route := range routes6 {
			fmt.Fprintf(fd, "%s\n", route)
		}
		fd.Close()
	}

	// Backup existing configs.
	prefix := fmt.Sprintf(".bak.%d.", time.Now().UnixNano())
	if n.Route4File.Name != "" {
		newName := prefix + n.Route4File.Name
		oldFile := path.Join(configDir, n.Route4File.Name)
		newFile := path.Join(configDir, newName)
		err := fileMove(oldFile, newFile)
		if err != nil {
			return err
		}
	}
	if n.Route6File.Name != "" {
		newName := prefix + n.Route6File.Name
		oldFile := path.Join(configDir, n.Route6File.Name)
		newFile := path.Join(configDir, newName)
		err := fileMove(oldFile, newFile)
		if err != nil {
			return err
		}
	}

	// Move new config in place.
	if len(routes4) != 0 {
		err := fileMove(tmp4Path, config4Path)
		if err != nil {
			return err
		}
	}
	if len(routes6) != 0 {
		err := fileMove(tmp6Path, config6Path)
		if err != nil {
			return err
		}
	}

	// Update the config in the structure.
	n.Route4File = nsRouteFile{}
	if len(routes4) != 0 {
		n.Route4File.Name = config4Name
		for _, route := range routes4 {
			n.Route4File.Routes = append(n.Route4File.Routes, strings.Fields(route))
		}
	}
	n.Route6File = nsRouteFile{}
	if len(routes6) != 0 {
		n.Route6File.Name = config6Name
		for _, route := range routes6 {
			n.Route6File.Routes = append(n.Route6File.Routes, strings.Fields(route))
		}
	}

	// Prune old backups beyond the retention count.
	if n.Route4File.Name != "" {
		pruneBackups(configDir, prefixBackupMatcher(n.Route4File.Name), backupRetention)
	}
	if n.Route6File.Name != "" {
		pruneBackups(configDir, prefixBackupMatcher(n.Route6File.Name), backupRetention)
	}

	return nil
}

// Set addresses to interface.
func (ns *networkScripts) SetIfaceAddresses(_ context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) (err error) {
	// Separate addresses by addr4 and addr6.
	var addrs4 []*net.IPNet
	var addrs6 []string
	for _, addr := range addrs {
		if addr.IP.To4() == nil {
			addrs6 = append(addrs6, addr.String())
		} else {
			addrs4 = append(addrs4, addr)
		}
	}

	// Find or create the interface. A backend must not silently no-op just
	// because it has not seen this interface before (e.g. a freshly attached
	// NIC), otherwise the caller gets a success with no persisted change.
	ifc := ns.EnsureInterface(iface)

	// Merge configs.
	config := make(map[string]string)
	for _, file := range ifc.IFFiles {
		err = mergo.Merge(&config, file.Config)
		if err != nil {
			return err
		}
	}

	// Delete existing configs.
	delete(config, "IPADDR6")
	delete(config, "IPV6ADDR")
	delete(config, "IPV6ADDR_SECONDARIES")
	delete(config, "IPV6_DEFAULTGW")
	delete(config, "GATEWAY")
	configMap := []string{""}
	for i := 0; i <= 255; i++ {
		configMap = append(configMap, strconv.Itoa(i))
	}
	for _, idx := range configMap {
		delete(config, fmt.Sprintf("IPADDR%s", idx))
		delete(config, fmt.Sprintf("PREFIX%s", idx))
		delete(config, fmt.Sprintf("NETMASK%s", idx))
		delete(config, fmt.Sprintf("BROADCAST%s", idx))
		delete(config, fmt.Sprintf("ARPCHECK%s", idx))
		delete(config, fmt.Sprintf("ARPUPDATE%s", idx))
	}

	// Add IP addresses.
	for idx, ip := range addrs4 {
		config[fmt.Sprintf("IPADDR%d", idx)] = ip.IP.String()
		prefix, _ := ip.Mask.Size()
		config[fmt.Sprintf("PREFIX%d", idx)] = strconv.Itoa(prefix)
		config[fmt.Sprintf("NETMASK%d", idx)] = net.IP(ip.Mask).String()
		config[fmt.Sprintf("BROADCAST%d", idx)] = getBroadcast(ip).String()
	}

	// Add IPv6 addresses.
	if len(addrs6) != 0 {
		config["IPV6ADDR"] = addrs6[0]
		addrs6 = addrs6[1:]
		if len(addrs6) != 0 {
			config["IPV6ADDR_SECONDARIES"] = strings.Join(addrs6, " ")
		}
	}

	// Set gateways.
	if gateway4 != nil {
		config["GATEWAY"] = gateway4.String()
	}
	if gateway6 != nil {
		config["IPV6_DEFAULTGW"] = gateway6.String()
	}

	// Try to save.
	err = ifc.Save(config, ns.ConfigDir, ns.backupRetention)
	if err != nil {
		return err
	}

	return
}

// Set static routes to interface.
func (ns *networkScripts) SetIfaceRoutes(_ context.Context, iface string, routes []*Route) (err error) {
	// Build route slices.
	var routes4 []string
	var routes6 []string
	for _, route := range routes {
		r := fmt.Sprintf("%s via %s metric %d", route.Destination.String(), route.Gateway, route.Metric)
		if route.Destination.IP.To4() == nil {
			routes6 = append(routes6, r)
		} else {
			routes4 = append(routes4, r)
		}
	}

	// Find or create the interface. A backend must not silently no-op just
	// because it has not seen this interface before (e.g. a freshly attached
	// NIC), otherwise the caller gets a success with no persisted change.
	ifc := ns.EnsureInterface(iface)

	// Save the routes.
	err = ifc.SaveRouteFiles(routes4, routes6, ns.ConfigDir, ns.backupRetention)
	if err != nil {
		return err
	}

	return
}

// Set DNS servers and search domains on interface.
func (ns *networkScripts) SetIfaceDNS(_ context.Context, iface string, servers []net.IP, searchDomains []string) (err error) {
	// Find or create the interface. A backend must not silently no-op just
	// because it has not seen this interface before (e.g. a freshly attached
	// NIC), otherwise the caller gets a success with no persisted change.
	ifc := ns.EnsureInterface(iface)

	// Merge configs.
	config := make(map[string]string)
	for _, file := range ifc.IFFiles {
		err = mergo.Merge(&config, file.Config)
		if err != nil {
			return err
		}
	}

	// Delete existing DNS and search-domain configs. network-scripts
	// stores resolvers as DNS1, DNS2, ... and the search list in DOMAIN.
	for key := range config {
		if strings.HasPrefix(key, "DNS") {
			delete(config, key)
		}
	}
	delete(config, "DOMAIN")
	delete(config, "PEERDNS")

	// Add DNS servers, numbered from 1 per the network-scripts format.
	idx := 1
	for _, ip := range servers {
		if ip == nil {
			continue
		}
		config[fmt.Sprintf("DNS%d", idx)] = ip.String()
		idx++
	}

	// On a DHCP interface, dhclient rewrites /etc/resolv.conf from the
	// lease on every renewal, which would override the DNS1/DNS2 set above.
	// PEERDNS=no tells the initscripts not to accept DHCP-provided resolvers
	// so the statically configured servers win. Only set it when we actually
	// have servers to enforce; when clearing, leaving PEERDNS unset restores
	// the default of honouring DHCP.
	if idx > 1 {
		config["PEERDNS"] = "no"
	}

	// Add search domains.
	if len(searchDomains) != 0 {
		config["DOMAIN"] = strings.Join(searchDomains, " ")
	}

	// Try to save.
	err = ifc.Save(config, ns.ConfigDir, ns.backupRetention)
	if err != nil {
		return err
	}

	return
}
