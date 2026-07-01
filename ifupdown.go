package netconfig

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

const ifUpDownConfig = "/etc/network/interfaces"

type ifInterface struct {
	Name      string
	Mode      string
	isDHCP    bool
	isPPP     bool
	Files     []string
	Addresses []*net.IPNet
	Gateway4  net.IP
	Gateway6  net.IP
	Routes    []*Route
	Config    map[string][]string
}

type ifUpDown struct {
	Interfaces      []*ifInterface
	BaseConfig      string
	BackupDir       string
	backupRetention int
}

// stanzaFamily reports the address family this interface's stanza configures.
// "iface eth0 inet dhcp" configures IPv4, "iface eth0 inet6 static" IPv6. An
// interface this backend has not seen has no stanza and reports "".
func (iface *ifInterface) stanzaFamily() string {
	fields := strings.Fields(iface.Mode)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "inet", "inet6":
		return fields[0]
	}
	return ""
}

// dhcpState reports whether each family's DHCP client is enabled. A stanza only
// ever configures one family, so at most one of these is ever true.
func (iface *ifInterface) dhcpState() (dhcp4, dhcp6 bool) {
	if !iface.isDHCP {
		return false, false
	}
	family := iface.stanzaFamily()
	return family == "inet", family == "inet6"
}

// setDHCP switches the stanza's method between "dhcp" and "static" for the
// family the stanza configures.
//
// Unlike netplan or networkd, an ifupdown interface is a set of stanzas and
// each names exactly one family, so this backend cannot express "DHCPv4 on,
// DHCPv6 on" from the single stanza it tracks per interface. Asking it to
// enable DHCP for the family its stanza does not configure is therefore an
// error rather than a silent no-op — the caller would otherwise be told the
// request succeeded while nothing was written. Disabling that other family is
// already true of a stanza that never configured it, so it is accepted.
func (iface *ifInterface) setDHCP(dhcp4, dhcp6 bool) error {
	if iface.isPPP {
		return fmt.Errorf("cannot change DHCP on PPP interface")
	}

	// An interface with no stanza yet gets one for the family being enabled.
	family := iface.stanzaFamily()
	if family == "" {
		switch {
		case dhcp4 && dhcp6:
			return fmt.Errorf("ifupdown cannot enable DHCP for both families on one stanza")
		case dhcp4:
			iface.Mode = "inet dhcp"
			iface.isDHCP = true
		case dhcp6:
			iface.Mode = "inet6 dhcp"
			iface.isDHCP = true
		default:
			iface.Mode = "inet static"
			iface.isDHCP = false
		}
		return nil
	}

	// Split the request into the family this stanza speaks for and the one it
	// does not. Only the former can be honored.
	enable, other := dhcp4, dhcp6
	if family == "inet6" {
		enable, other = dhcp6, dhcp4
	}
	if other {
		return fmt.Errorf("ifupdown cannot enable DHCP for the other family on an %q stanza for %s", family, iface.Name)
	}

	fields := strings.Fields(iface.Mode)
	method := ""
	if len(fields) > 1 {
		method = fields[1]
	}
	switch method {
	case "loopback", "ppp", "tunnel", "wvdial":
		return fmt.Errorf("cannot change DHCP on %q interface %s", method, iface.Name)
	}

	switch {
	case enable && method != "dhcp":
		iface.Mode = family + " dhcp"
		iface.isDHCP = true
	case !enable && method == "dhcp":
		iface.Mode = family + " static"
		iface.isDHCP = false
	}
	return nil
}

// Either retreives an existing interface, or makes a new one.
func (i *ifUpDown) EnsureInterface(name string) *ifInterface {
	// Find existing interface and return it.
	for _, iface := range i.Interfaces {
		if iface.Name == name {
			return iface
		}
	}

	// Make a new interface as one wasn't found. Seed it with the base config
	// file so Save (which iterates iface.Files) actually persists the new
	// block; without a file the interface would be held only in memory and
	// silently dropped on write.
	iface := &ifInterface{
		Name:   name,
		Files:  []string{i.BaseConfig},
		Config: make(map[string][]string),
	}
	i.Interfaces = append(i.Interfaces, iface)
	return iface
}

// Parses an ifupdown interface file.
func (i *ifUpDown) ReadFile(configFile string) error {
	// Open the config file.
	fd, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer fd.Close()

	// Parse the file.
	var iface *ifInterface
	var address *net.IPNet
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()

		// Get index of comments and remove them.
		idx := strings.IndexByte(line, '#')
		if idx != -1 {
			line = line[:idx]
		}

		// Trim whitespace.
		line = strings.TrimSpace(line)

		// Ignore blank lines.
		if len(line) == 0 {
			continue
		}

		// Parse fields.
		fields := strings.Fields(line)
		switch fields[0] {
		// For the global configs, we just skip as we are not reconstructing
		// the entire file when saving changes.
		case "auto", "allow-hotplug":
			continue

		// On source directory, read all files in the specified directory.
		case "source-directory":
			// If no directory, return error.
			if len(fields) < 2 {
				return fmt.Errorf("invalid source directory syntax")
			}

			// Try to read the directory files.
			unsortedEntries, err := os.ReadDir(fields[1])
			if err != nil {
				return err
			}

			// Sort by name.
			entries := sortableDirEntries(unsortedEntries)
			sort.Sort(entries)

			// Read each file.
			for _, entry := range entries {
				// Skip directories.
				if entry.IsDir() {
					continue
				}

				filePath := path.Join(fields[1], entry.Name())
				err := i.ReadFile(filePath)
				if err != nil {
					return err
				}
			}

		// On source, read file specified.
		case "source":
			// If no file specified, error.
			if len(fields) < 2 {
				return fmt.Errorf("invalid source file syntax")
			}

			// Read the file specified.
			err := i.ReadFile(fields[1])
			if err != nil {
				return err
			}

		// For interface configs, set current interface and parse type.
		case "iface", "interface":
			// We require at least the interface name.
			if len(fields) < 2 {
				return fmt.Errorf("invalid interface syntax")
			}

			// Finalize any addresses.
			if address != nil {
				iface.Addresses = append(iface.Addresses, address)
				address = nil
			}

			// Ensure interface is created.
			ifname := fields[1]
			idx := strings.IndexByte(ifname, ':')
			if idx != -1 {
				ifname = ifname[:idx]
			}
			iface = i.EnsureInterface(ifname)

			// Track the file the interface has configurations in. A
			// dual-stack interface has separate "inet"/"inet6" stanzas that
			// commonly live in the same file, so only record a file once per
			// interface: Save processes iface.Files by index using tmp/backup
			// names computed a single time up front, and reprocessing the
			// same path a second time would clobber the backup of the true
			// original with the already-rewritten intermediate content.
			if !stringInSlice(iface.Files, configFile) {
				iface.Files = append(iface.Files, configFile)
			}

			// Determine type.
			for _, field := range fields[2:] {
				if field == "dhcp" {
					iface.isDHCP = true
				} else if field == "ppp" {
					iface.isPPP = true
				}
			}

			// Save mode for cases where we need to write.
			iface.Mode = strings.Join(fields[2:], " ")

		// Parse assigned addresses.
		case "address":
			// We require an address field.
			if len(fields) < 2 {
				return fmt.Errorf("invalid address syntax")
			}

			// If no interface, fail.
			if iface == nil {
				return fmt.Errorf("no interface to assign address to")
			}

			// If an address to be parsed is there, add to the list of addresses.
			if address != nil {
				iface.Addresses = append(iface.Addresses, address)
				address = nil
			}

			// If not cider, parse IP.
			if !strings.Contains(fields[1], "/") {
				address = &net.IPNet{
					IP: net.ParseIP(fields[1]),
				}
				if address.IP == nil {
					return fmt.Errorf("invalid IP provided: %s", fields[1])
				}
				if address.IP.To4() == nil {
					address.Mask = net.CIDRMask(128, 128)
				} else {
					address.Mask = net.CIDRMask(32, 32)
				}
			} else {
				var ip net.IP
				ip, address, err = net.ParseCIDR(fields[1])
				if err != nil {
					return err
				}
				address.IP = ip
			}

		// If an netmask is set, assign to the last parsed address.
		case "netmask":
			// We require an netmask field.
			if len(fields) < 2 {
				return fmt.Errorf("invalid netmask syntax")
			}

			// Require an address.
			if address == nil {
				return fmt.Errorf("no address to apply netmask")
			}

			// If the netmask is an ipmask, parse that.
			if strings.Contains(fields[1], ".") {
				ipMask := net.ParseIP(fields[1]).To4()
				if ipMask == nil {
					return fmt.Errorf("invalid netmask: %s", fields[1])
				}
				address.Mask = net.IPMask(ipMask)
			} else {
				// This is just the prefix.
				prefix, err := strconv.Atoi(fields[1])
				if err != nil {
					return err
				}
				if address.IP.To4() == nil {
					address.Mask = net.CIDRMask(prefix, 128)
				} else {
					address.Mask = net.CIDRMask(prefix, 32)
				}
			}

		// If an gateway is defined, assign according to family.
		case "gateway":
			// We require an gateway field.
			if len(fields) < 2 {
				return fmt.Errorf("invalid gateway syntax")
			}

			// Parse the gateway.
			gateway := net.ParseIP(fields[1])
			if gateway == nil {
				return fmt.Errorf("failed to parse gateway: %s", fields[1])
			}

			// Add the gateway by family.
			if gateway.To4() == nil {
				iface.Gateway6 = gateway
			} else {
				iface.Gateway4 = gateway
			}

		// For other configurations, save to the interface key value config.
		default:
			// All field sshould have key and value.
			if len(fields) < 2 {
				return fmt.Errorf("invalid syntax")
			}

			// If no interface, skip.
			if iface == nil {
				continue
			}

			// If up script, try parsing fields.
			if fields[0] == "up" && len(fields) >= 4 {
				// If the route command is called, see if we can parse
				if fields[1] == "route" {
					var dst *net.IPNet
					var gateway net.IP
					metric := int(256)
					isAdd := false
					fieldLen := len(fields)
					for f := 2; f < fieldLen; f++ {
						field := fields[f]
						if f+1 >= fieldLen {
							continue
						}
						switch field {
						case "add":
							isAdd = true
						case "-net", "-host":
							continue
						case "netmask":
							f++
							// A netmask before any destination is malformed; skip
							// it rather than dereferencing a nil dst.
							if dst == nil {
								continue
							}
							ipMask := net.ParseIP(fields[f]).To4()
							if ipMask == nil {
								continue
							}
							dst.Mask = net.IPMask(ipMask)
						case "gw":
							f++
							gateway = net.ParseIP(fields[f])
						case "metric":
							f++
							metric, err = strconv.Atoi(fields[f])
							if err != nil {
								metric = 256
							}
						default:
							// If no destination parsed, check if we can parse one here.
							if dst != nil {
								continue
							}
							// The destination is the current field (e.g. the token
							// after "-net"/"-host"), not the next one.
							host := fields[f]
							if strings.Contains(host, "/") {
								ip, ipnet, err := net.ParseCIDR(host)
								if err != nil {
									continue
								}
								ipnet.IP = ip
								dst = ipnet
							} else {
								dst = &net.IPNet{
									IP: net.ParseIP(host),
								}
								if dst.IP == nil {
									dst = nil
									continue
								}
								if dst.IP.To4() == nil {
									dst.Mask = net.CIDRMask(128, 128)
								} else {
									dst.Mask = net.CIDRMask(32, 32)
								}
							}
						}
					}

					// If we found that we're adding and all needed
					// fields are parsed. Add route and skip adding
					// key value config.
					if isAdd && dst != nil && gateway != nil {
						r := new(Route)
						r.Destination = dst
						r.Gateway = gateway
						r.Metric = metric
						iface.Routes = append(iface.Routes, r)
						continue
					}

					// On the ip command, this can either be an route
					// or an address.
				} else if fields[1] == "ip" {
					isRoute := false
					isAddr := false
					isAdd := false
					thisDev := false
					var address *net.IPNet
					var dst *net.IPNet
					var gateway net.IP
					metric := int(256)
					fieldLen := len(fields)
					for f := 2; f < fieldLen; f++ {
						field := fields[f]
						if f+1 >= fieldLen {
							continue
						}
						if field == "addr" || field == "address" {
							isAddr = true
						} else if field == "route" {
							isRoute = true
						} else if field == "add" {
							// typically the address field for both
							// routes and addresses is right after
							// the add command.
							isAdd = true
							f++
							ip, network, err := net.ParseCIDR(fields[f])
							if err != nil {
								continue
							}
							network.IP = ip
							if isAddr {
								address = network
							} else if isRoute {
								dst = network
							}
						} else if field == "dev" {
							f++
							devName := fields[f]
							if devName == "$IFACE" {
								thisDev = true
							} else if devName == iface.Name {
								thisDev = true
							}
						} else if field == "via" {
							f++
							gateway = net.ParseIP(fields[f])
						} else if field == "metric" {
							f++
							metric, err = strconv.Atoi(fields[f])
							if err != nil || metric == 0 {
								metric = 256
							}
						}
					}

					// If we parsed an add command, add parsed info.
					if isAdd {
						// If valid route or address, add and skip
						// adding the key/value config.
						if isRoute && dst != nil && gateway != nil {
							r := new(Route)
							r.Destination = dst
							r.Gateway = gateway
							r.Metric = metric
							iface.Routes = append(iface.Routes, r)
							continue
						} else if isAddr && address != nil && thisDev {
							iface.Addresses = append(iface.Addresses, address)
							continue
						}
					}
				}
			}

			// Check if the down script can be skipped due to route or address.
			if fields[0] == "down" && len(fields) >= 4 {
				// Parse route del commands to see if its removing a route
				// that was added.
				if fields[1] == "route" {
					var dst *net.IPNet
					isDel := false
					fieldLen := len(fields)
					for f := 2; f < fieldLen; f++ {
						field := fields[f]
						if f+1 >= fieldLen {
							continue
						}
						switch field {
						case "del":
							isDel = true
						case "-net", "-host":
							continue
						case "netmask":
							f++
							// A netmask before any destination is malformed; skip
							// it rather than dereferencing a nil dst.
							if dst == nil {
								continue
							}
							ipMask := net.ParseIP(fields[f]).To4()
							if ipMask == nil {
								continue
							}
							dst.Mask = net.IPMask(ipMask)
						default:
							// If no destination parsed, check if we can parse one here.
							if dst != nil {
								continue
							}
							// The destination is the current field (e.g. the token
							// after "-net"/"-host"), not the next one.
							host := fields[f]
							if strings.Contains(host, "/") {
								ip, ipnet, err := net.ParseCIDR(host)
								if err != nil {
									continue
								}
								ipnet.IP = ip
								dst = ipnet
							} else {
								dst = &net.IPNet{
									IP: net.ParseIP(host),
								}
								if dst.IP == nil {
									dst = nil
									continue
								}
								if dst.IP.To4() == nil {
									dst.Mask = net.CIDRMask(128, 128)
								} else {
									dst.Mask = net.CIDRMask(32, 32)
								}
							}
						}
					}

					// If route del and we parsed the desitnation,
					// confirm the destination is being added and
					// ignore this key/value add if it is.
					if isDel && dst != nil {
						exists := false
						for _, route := range iface.Routes {
							if route.Destination.Contains(dst.IP) {
								exists = true
								break
							}
						}

						if exists {
							continue
						}
					}

					// On IP del command, parse and determine if we should
					// skip adding key/value.
				} else if fields[1] == "ip" {
					isRoute := false
					isAddr := false
					isDel := false
					thisDev := false
					var address *net.IPNet
					var dst *net.IPNet
					fieldLen := len(fields)
					for f := 2; f < fieldLen; f++ {
						field := fields[f]
						if f+1 >= fieldLen {
							continue
						}
						if field == "addr" || field == "address" {
							isAddr = true
						} else if field == "route" {
							isRoute = true
						} else if field == "del" || field == "delete" {
							isDel = true
							f++
							ip, network, err := net.ParseCIDR(fields[f])
							if err != nil {
								continue
							}
							network.IP = ip
							if isAddr {
								address = network
							} else if isRoute {
								dst = network
							}
						} else if field == "dev" {
							f++
							devName := fields[f]
							if devName == "$IFACE" {
								thisDev = true
							} else if devName == iface.Name {
								thisDev = true
							}
						}
					}

					// If this is an del and the parsed information exists
					// in the appropiate bucket. Skip adding key/value.
					if isDel {
						if isRoute && dst != nil {
							continue
						} else if isAddr && address != nil && thisDev {
							continue
						}
					}
				}
			}

			// Get the name and value.
			name := fields[0]
			value := strings.Join(fields[1:], " ")

			// Add config.
			config := iface.Config[name]
			config = append(config, value)
			iface.Config[name] = config
		}
	}

	// Finalize any addresses.
	if address != nil {
		iface.Addresses = append(iface.Addresses, address)
		address = nil
	}

	return nil
}

// Setup an ifupdown config tool.
func newIfUpDown(backupRetention int) (i *ifUpDown, err error) {
	i = new(ifUpDown)
	i.backupRetention = backupRetention
	i.BaseConfig = ifUpDownConfig
	i.BackupDir = ifUpDownConfig + ".backup"
	err = i.ReadFile(i.BaseConfig)
	if err != nil {
		return nil, err
	}
	return
}

// Get interfaces configured.
func (i *ifUpDown) GetInterfaces() (interfaces []*Interface, err error) {
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

	for _, iface := range i.Interfaces {
		i := new(Interface)
		i.Name = iface.Name
		i.DHCP4, i.DHCP6 = iface.dhcpState()

		// Discover the interface name and mac address.
		for _, link := range links {
			if link.Attrs().Name == iface.Name {
				i.MAC = link.Attrs().HardwareAddr
				i.Link = link
			}
		}

		// Add addresses.
		for _, address := range iface.Addresses {
			i.Addresses = append(i.Addresses, address)
		}

		// Add gateways.
		i.Gateway4 = iface.Gateway4
		i.Gateway6 = iface.Gateway6

		// Add DNS servers and search domains from the resolvconf stanzas.
		for _, val := range iface.Config["dns-nameservers"] {
			for _, field := range strings.Fields(val) {
				if ip := net.ParseIP(field); ip != nil {
					i.DNS = append(i.DNS, ip)
				}
			}
		}
		for _, val := range iface.Config["dns-search"] {
			i.SearchDomains = append(i.SearchDomains, strings.Fields(val)...)
		}

		// Add static routes.
		i.Routes = iface.Routes

		// Add interface.
		interfaces = append(interfaces, i)
	}
	return
}

// Write our interface config to the specified file.
func (iface *ifInterface) Write(fd *os.File) error {
	// Write the interface config.
	if iface.Mode != "" {
		fmt.Fprintf(fd, "iface %s %s\n", iface.Name, iface.Mode)
	} else {
		fmt.Fprintf(fd, "iface %s\n", iface.Name)
	}

	// Add first address of each family.
	first4 := true
	first6 := true
	for _, addr := range iface.Addresses {
		if addr.IP.To4() == nil {
			if !first6 {
				continue
			}
			first6 = false
			fmt.Fprintf(fd, "\taddress %s\n", addr.String())
		} else {
			if !first4 {
				continue
			}
			first4 = false
			fmt.Fprintf(fd, "\taddress %s\n", addr.String())
		}
	}

	// Add gateways.
	if iface.Gateway4 != nil {
		fmt.Fprintf(fd, "\tgateway %s\n", iface.Gateway4.String())
	}
	if iface.Gateway6 != nil {
		fmt.Fprintf(fd, "\tgateway %s\n", iface.Gateway6.String())
	}

	// Add key/value configs.
	var keys []string
	hasUp := false
	hasDown := false
	for key := range iface.Config {
		if key == "up" {
			hasUp = true
			continue
		}
		if key == "down" {
			hasDown = true
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if hasUp {
		keys = append(keys, "up")
	}
	if hasDown {
		keys = append(keys, "down")
	}
	for _, key := range keys {
		values := iface.Config[key]
		for _, value := range values {
			fmt.Fprintf(fd, "\t%s %s\n", key, value)
		}
	}

	// Add any additional IP addresses via the ip command.
	first4 = false
	first6 = false
	for _, addr := range iface.Addresses {
		if addr.IP.To4() == nil {
			if !first6 {
				first6 = true
				continue
			}
			fmt.Fprintf(fd, "\tup ip -6 addr add %s dev $IFACE\n", addr.String())
			fmt.Fprintf(fd, "\tdown ip -6 addr del %s dev $IFACE\n", addr.String())
		} else {
			if !first4 {
				first4 = true
				continue
			}
			fmt.Fprintf(fd, "\tup ip addr add %s dev $IFACE\n", addr.String())
			fmt.Fprintf(fd, "\tdown ip addr del %s dev $IFACE\n", addr.String())
		}
	}

	// Add static routes.
	for _, route := range iface.Routes {
		if route.Destination.IP.To4() == nil {
			fmt.Fprintf(fd, "\tup ip -6 route add %s via %s metric %d dev $IFACE\n", route.Destination.String(), route.Gateway.String(), route.Metric)
			fmt.Fprintf(fd, "\tdown ip -6 route del %s via %s metric %d dev $IFACE\n", route.Destination.String(), route.Gateway.String(), route.Metric)
		} else {
			fmt.Fprintf(fd, "\tup ip route add %s via %s metric %d dev $IFACE\n", route.Destination.String(), route.Gateway.String(), route.Metric)
			fmt.Fprintf(fd, "\tdown ip route del %s via %s metric %d dev $IFACE\n", route.Destination.String(), route.Gateway.String(), route.Metric)
		}
	}
	fmt.Fprintln(fd)

	return nil
}

// Save the interface config to the files read.
func (iface *ifInterface) Save(backupDir string, backupRetention int) error {
	// Confirm the backup dir is created.
	if _, serr := os.Stat(backupDir); os.IsNotExist(serr) {
		err := os.Mkdir(backupDir, 0755)
		if err != nil {
			return err
		}
	}

	// Setup prefix and for each file the interface was found in,
	// update the files.
	prefixTmp := fmt.Sprintf(".tmp.%d.", time.Now().UnixNano())
	prefixBak := fmt.Sprintf(".bak.%d.", time.Now().UnixNano())
	for i, filePath := range iface.Files {
		// Get temporary file path.
		file := path.Base(filePath)
		tmp := prefixTmp + file
		tmpPath := path.Join(backupDir, tmp)
		bak := prefixBak + file
		bakPath := path.Join(backupDir, bak)

		// Open tmp file for writing.
		fdw, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}

		// Check if the config file exists.
		fileExists := true
		if _, serr := os.Stat(filePath); os.IsNotExist(serr) {
			fileExists = false
		}

		// If the file doesn't exist, then we're not trying to replace
		// the interface config in a file of potential other interface configs.
		if !fileExists {
			// Only write our configs on the first file.
			if i == 0 {
				fmt.Fprintf(fdw, "auto %s\n", iface.Name)
				fmt.Fprintf(fdw, "allow-hotplug %s\n\n", iface.Name)
				iface.Write(fdw)
			}
		} else {
			// The file does exist, so we should read the original file
			// and try to pull out the original interface config ignoring
			// other interface configs.

			// Open file for reading.
			fd, err := os.Open(filePath)
			if err != nil {
				return err
			}

			// Scan original file.
			scanner := bufio.NewScanner(fd)
			foundIface := false
			wroteIface := false
			blankLineCount := 0
			for scanner.Scan() {
				line := scanner.Text()
				origLine := line

				// Get index of comments and remove them.
				idx := strings.IndexByte(line, '#')
				comment := false
				if idx != -1 {
					comment = true
					line = line[:idx]
				}

				// Trim whitespace.
				line = strings.TrimSpace(line)

				// Ignore blank lines, writing them back to the file.
				if len(line) == 0 {
					// If the blank line is actually a comment line,
					// we do not want to apply the blank line limit.
					if comment {
						fmt.Fprintln(fdw, origLine)
						blankLineCount = 0
						continue
					}

					// Increment the count of blank lines, allowing 1
					// spacing apart.
					blankLineCount++
					if blankLineCount <= 1 {
						fmt.Fprintln(fdw, origLine)
					}
					continue
				} else {
					// Reset the count as this isn't a blank line.
					blankLineCount = 0
				}

				// Parse fields.
				fields := strings.Fields(line)
				switch fields[0] {
				// On the global configs, check if the current interface
				// is in its list of interfaces. If it is not, we should
				// ensure we write the config and continue to the next
				// interface.
				case "auto", "allow-hotplug":
					containsIface := false
					for _, ifname := range fields[1:] {
						idx := strings.IndexByte(ifname, ':')
						if idx != -1 {
							ifname = ifname[:idx]
						}
						if iface.Name == ifname {
							containsIface = true
						}
					}
					if containsIface && foundIface && !wroteIface {
						wroteIface = true
						foundIface = false
						if i == 0 {
							err = iface.Write(fdw)
							if err != nil {
								return err
							}
						}
					}
					fmt.Fprintln(fdw, origLine)

				// On the interface config, check if its this interface
				// so we can determine when to write our configs.
				// If its not this interface, we will just write the config
				// line for line.
				case "iface", "interface":
					// We require at least the interface name.
					if len(fields) < 2 {
						fmt.Fprintln(fdw, origLine)
						continue
					}

					// Check if this is the interface.
					ifname := fields[1]
					idx := strings.IndexByte(ifname, ':')
					if idx != -1 {
						ifname = ifname[:idx]
					}
					if iface.Name == ifname {
						foundIface = true
					} else if foundIface && !wroteIface {
						wroteIface = true
						foundIface = false
						if i == 0 {
							err = iface.Write(fdw)
							if err != nil {
								return err
							}
						}
					}
					if !foundIface {
						fmt.Fprintln(fdw, origLine)
					}

				// On default, its a regular config which we will skip
				// when we're on our interface, but write line by line for
				// other interfaces.
				default:
					if foundIface {
						continue
					}
					fmt.Fprintln(fdw, origLine)
				}
			}

			// if we did not write the interface, write it.
			if !wroteIface {
				err = iface.Write(fdw)
				if err != nil {
					return err
				}
			}

			// Close the open file.
			fd.Close()
		}

		// We're done writing, so let's close files.
		fdw.Close()

		// Backup existing config.
		if fileExists {
			err = fileMove(filePath, bakPath)
			if err != nil {
				return err
			}
		}

		// Move new config in place.
		err = fileMove(tmpPath, filePath)
		if err != nil {
			return err
		}

		// Prune old backups of this config file beyond the retention count.
		pruneBackups(backupDir, prefixBackupMatcher(file), backupRetention)
	}

	return nil
}

// Set the DHCP client state on an interface.
func (i *ifUpDown) SetIfaceDHCP(_ context.Context, iface string, dhcp4, dhcp6 bool) (err error) {
	// Find or create the interface. A backend must not silently no-op just
	// because it has not seen this interface before (e.g. a freshly attached
	// NIC), otherwise the caller gets a success with no persisted change.
	ifc := i.EnsureInterface(iface)

	// Switching to DHCP hands addressing to the lease, so the static addresses
	// and gateways the stanza carried are dropped rather than written back
	// under a "dhcp" method that has no address option to hold them.
	dhcp := dhcp4 || dhcp6
	if err = ifc.setDHCP(dhcp4, dhcp6); err != nil {
		return err
	}
	if dhcp {
		ifc.Addresses = nil
		ifc.Gateway4 = nil
		ifc.Gateway6 = nil
	}

	// Save the interface config.
	return ifc.Save(i.BackupDir, i.backupRetention)
}

// renewDHCP restarts the interface through ifupdown so the "dhcp" method that
// was just written to its stanza is acted on and a lease is acquired. ifup on
// an already-up interface is a no-op, so it is taken down first.
func (i *ifUpDown) renewDHCP(ctx context.Context, iface string) error {
	// ifdown on an interface that is already down exits non-zero, which is not
	// a failure of this call — down is the state ifup wants it in.
	_, _ = runCommand(ctx, "ifdown", iface)
	_, err := runCommand(ctx, "ifup", iface)
	return err
}

// Set addresses to interface.
func (i *ifUpDown) SetIfaceAddresses(_ context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) (err error) {
	// Find the interface.
	for _, ifc := range i.Interfaces {
		if ifc.Name != iface {
			continue
		}

		// Ensure we can adjust addresses. An ifupdown "dhcp" stanza takes no
		// address option, so unlike netplan or networkd this backend cannot
		// carry a static address alongside a lease on the same stanza. Call
		// SetIfaceDHCP to convert the stanza to static first.
		if ifc.isDHCP {
			return fmt.Errorf("cannot change addresses on DHCP interface")
		} else if ifc.isPPP {
			return fmt.Errorf("cannot change addresses on PPP interface")
		}

		// Set provided addresses.
		ifc.Addresses = addrs
		ifc.Gateway4 = gateway4
		ifc.Gateway6 = gateway6

		// Save the interface config.
		err = ifc.Save(i.BackupDir, i.backupRetention)
		if err != nil {
			return err
		}
	}

	return nil
}

// Set static routes to interface.
func (i *ifUpDown) SetIfaceRoutes(_ context.Context, iface string, routes []*Route) (err error) {
	// Find the interface.
	for _, ifc := range i.Interfaces {
		if ifc.Name != iface {
			continue
		}

		// Ensure we can adjust static routes.
		if ifc.isDHCP {
			return fmt.Errorf("cannot change static routes on DHCP interface")
		} else if ifc.isPPP {
			return fmt.Errorf("cannot change static routes on PPP interface")
		}

		// Set provided static routes.
		ifc.Routes = routes

		// Save the interface config.
		err = ifc.Save(i.BackupDir, i.backupRetention)
		if err != nil {
			return err
		}
	}

	return nil
}

// Set DNS servers and search domains on interface. ifupdown relies on the
// resolvconf integration, which reads the dns-nameservers and dns-search
// stanzas from the interface block.
func (i *ifUpDown) SetIfaceDNS(_ context.Context, iface string, servers []net.IP, searchDomains []string) (err error) {
	// Find or create the interface. A backend must not silently no-op just
	// because it has not seen this interface before (e.g. a freshly attached
	// NIC), otherwise the caller gets a success with no persisted change.
	ifc := i.EnsureInterface(iface)

	// Ensure we can adjust configuration.
	if ifc.isDHCP {
		return fmt.Errorf("cannot change DNS on DHCP interface")
	} else if ifc.isPPP {
		return fmt.Errorf("cannot change DNS on PPP interface")
	}

	// Replace the DNS stanzas.
	delete(ifc.Config, "dns-nameservers")
	delete(ifc.Config, "dns-search")
	dns := ipStrings(servers)
	if len(dns) != 0 {
		ifc.Config["dns-nameservers"] = []string{strings.Join(dns, " ")}
	}
	if len(searchDomains) != 0 {
		ifc.Config["dns-search"] = []string{strings.Join(searchDomains, " ")}
	}

	// The dns-nameservers/dns-search stanzas are not understood by ifup
	// itself; they are consumed by the resolvconf integration hook. On a host
	// without the resolvconf package installed (common on stock Ubuntu 14.04
	// servers) these stanzas are inert and the persisted DNS never reaches
	// /etc/resolv.conf on boot. Warn so the operator knows the write alone is
	// not sufficient.
	if (len(dns) != 0 || len(searchDomains) != 0) && !resolvconfInstalled() {
		logger.Printf("IfUpDown: resolvconf not found; dns-nameservers/dns-search in %s will not take effect on reboot without the resolvconf package", ifUpDownConfig)
	}

	// Save the interface config.
	err = ifc.Save(i.BackupDir, i.backupRetention)
	if err != nil {
		return err
	}

	return nil
}

// resolvconfInstalled reports whether the resolvconf binary is available on
// PATH, which the ifupdown dns-* stanzas depend on to update the live resolver.
func resolvconfInstalled() bool {
	_, err := exec.LookPath("resolvconf")
	return err == nil
}
