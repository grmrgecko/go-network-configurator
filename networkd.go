package netconfig

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"gopkg.in/ini.v1"
)

type networkdNetwork struct {
	Config   *ini.File
	Name     string
	MAC      net.HardwareAddr
	Link     netlink.Link
	File     string
	SubFiles []string
}

type networkd struct {
	Networks        []*networkdNetwork
	configDir       string
	backupRetention int
}

// Verify try parsing networkd configurations.
func newNetworkd(backupRetention int) (n *networkd, err error) {
	// Try to parse the networkd configurations. /etc/systemd/network is the
	// durable, admin-facing source of truth and is tried first so persisted
	// changes actually survive a reboot; /run/systemd/network is a volatile
	// tmpfs directory that systemd-networkd also honors and is only used as a
	// fallback, otherwise a host with any file in /run/systemd/network would
	// have its real /etc/systemd/network configuration silently ignored.
	n, err = readNetworkdConfigDirectory("/etc/systemd/network")
	if err != nil {
		n, err = readNetworkdConfigDirectory("/run/systemd/network")
		if err != nil {
			n, err = readNetworkdConfigDirectory("/lib/systemd/network")
		}
	}
	if n != nil {
		n.backupRetention = backupRetention
	}
	return
}

// Read an systemd-networkd configuration directory for network configuration files.
func readNetworkdConfigDirectory(dirPath string) (nd *networkd, err error) {
	// Try to read the directory files.
	unsortedEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}

	// Sort by name.
	entries := sortableDirEntries(unsortedEntries)
	sort.Sort(entries)

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

	// Read each network file.
	var networks []*networkdNetwork
	for _, entry := range entries {
		// If not an network file, skip.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".network") {
			continue
		}

		// Get the config path and sub config path.
		configPath := path.Join(dirPath, entry.Name())
		configSubPath := configPath + ".d"

		// Find any sub configuration files.
		var subFiles []string
		var subPaths []interface{}
		if stat, serr := os.Stat(configSubPath); !os.IsNotExist(serr) && stat.IsDir() {
			// Try to read the directory files.
			unsortedEntries, err = os.ReadDir(configSubPath)
			if err != nil {
				return
			}

			// Sort by name.
			subEntries := sortableDirEntries(unsortedEntries)
			sort.Sort(subEntries)
			for _, subEnt := range subEntries {
				// If not an network file, skip.
				if subEnt.IsDir() || !strings.HasSuffix(subEnt.Name(), ".conf") {
					continue
				}
				subFiles = append(subFiles, subEnt.Name())
				subPath := path.Join(configSubPath, subEnt.Name())
				subPaths = append(subPaths, subPath)
			}
		}

		// Parse the config files found.
		var cfg *ini.File
		opts := ini.LoadOptions{
			AllowShadows:               true,
			KeyValueDelimiters:         "=",
			KeyValueDelimiterOnWrite:   "=",
			ChildSectionDelimiter:      ".",
			AllowNonUniqueSections:     true,
			AllowDuplicateShadowValues: true,
		}
		cfg, err = ini.LoadSources(opts, configPath, subPaths...)
		if err != nil {
			return
		}

		// The config should have an network and match section.
		if !cfg.HasSection("Network") || !cfg.HasSection("Match") {
			return nil, fmt.Errorf("the configuration is missing key sections: %s", configPath)
		}

		// Discover the interface name and mac address.
		var mac net.HardwareAddr
		var foundLink netlink.Link

		// Get the match section needed.
		match, _ := cfg.GetSection("Match")

		// Find the name in the match section.
		var name string
		nameKey, _ := match.GetKey("Name")
		if nameKey != nil {
			name = nameKey.String()
		}

		// If the name wasn't in the match section, try finding
		// by MAC address.'
		if name == "" {
			// Get the MAC address from the match section.
			var macAddr string
			macKey, _ := match.GetKey("MACAddress")
			if macKey != nil {
				macAddr = macKey.String()
			}

			// Try parsing the MAC.
			mac, err = net.ParseMAC(macAddr)
			if err != nil {
				return nil, fmt.Errorf("unable to parse mac address %s: %v", macAddr, err)
			}

			// Find the matching link.
			for _, link := range links {
				if bytes.Equal(link.Attrs().HardwareAddr, mac) {
					foundLink = link
					name = link.Attrs().Name
				}
			}
		}

		/// If the link wasn't found above, its likely to be found by name.
		if foundLink == nil {
			for _, link := range links {
				if link.Attrs().Name == name {
					foundLink = link
				}
			}
		}

		// Add to list of networks.
		networks = append(networks, &networkdNetwork{
			Config:   cfg,
			Name:     name,
			MAC:      mac,
			Link:     foundLink,
			File:     entry.Name(),
			SubFiles: subFiles,
		})
	}

	// If no networks were parsed, this directory has no configurations.
	if len(networks) == 0 {
		return nil, fmt.Errorf("no configuration files exist")
	}

	// Return networkd.
	nd = new(networkd)
	nd.Networks = networks
	nd.configDir = dirPath
	return
}

// Get interfaces configured.
func (nd *networkd) GetInterfaces() (interfaces []*Interface, err error) {
	// Add networks to the list.
	for _, n := range nd.Networks {
		// Setup the new interface.
		i := new(Interface)
		i.Name = n.Name
		i.MAC = n.MAC
		i.Link = n.Link

		// Find IP addresses in the network and address sections.
		// Also parse any routes.
		for _, sec := range n.Config.Sections() {
			switch sec.Name() {
			// IF this is an network section, try to find addresses.
			case "Network":
				// Find the addresses in the address key.
				addressKey, _ := sec.GetKey("Address")
				if addressKey == nil {
					continue
				}
				addresses := addressKey.ValueWithShadows()

				// Add addresses.
				for _, addr := range addresses {
					// Per the spec, clear on empty.
					if addr == "" {
						i.Addresses = nil
						continue
					}
					ip, ipnet, err := net.ParseCIDR(addr)
					if err != nil {
						continue
					}
					ipnet.IP = ip
					i.Addresses = append(i.Addresses, ipnet)
				}

				// Find DNS servers and search domains.
				if dnsKey, _ := sec.GetKey("DNS"); dnsKey != nil {
					for _, d := range dnsKey.ValueWithShadows() {
						if ip := net.ParseIP(d); ip != nil {
							i.DNS = append(i.DNS, ip)
						}
					}
				}
				if domainsKey, _ := sec.GetKey("Domains"); domainsKey != nil {
					i.SearchDomains = append(i.SearchDomains, strings.Fields(domainsKey.String())...)
				}

				// Find the gateways in the gateway key.
				gatewayKey, _ := sec.GetKey("Gateway")
				if gatewayKey == nil {
					continue
				}
				gateways := gatewayKey.ValueWithShadows()

				// Add gateways.
				for _, gatewayIP := range gateways {
					gateway := net.ParseIP(gatewayIP)
					if gateway == nil {
						continue
					}
					if gateway.To4() == nil {
						i.Gateway6 = gateway
					} else {
						i.Gateway4 = gateway
					}
				}

			// IF this is an address section, try to find addresses.
			case "Address":
				// Find the addresses in the address key.
				addressKey, _ := sec.GetKey("Address")
				if addressKey == nil {
					continue
				}
				addresses := addressKey.ValueWithShadows()

				// Add addresses.
				for _, addr := range addresses {
					// Per the spec, clear on empty.
					if addr == "" {
						i.Addresses = nil
						continue
					}
					ip, ipnet, err := net.ParseCIDR(addr)
					if err != nil {
						continue
					}
					ipnet.IP = ip
					i.Addresses = append(i.Addresses, ipnet)
				}

				// Find DNS servers and search domains.
				if dnsKey, _ := sec.GetKey("DNS"); dnsKey != nil {
					for _, d := range dnsKey.ValueWithShadows() {
						if ip := net.ParseIP(d); ip != nil {
							i.DNS = append(i.DNS, ip)
						}
					}
				}
				if domainsKey, _ := sec.GetKey("Domains"); domainsKey != nil {
					i.SearchDomains = append(i.SearchDomains, strings.Fields(domainsKey.String())...)
				}

				// Find the gateways in the gateway key.
				gatewayKey, _ := sec.GetKey("Gateway")
				if gatewayKey == nil {
					continue
				}
				gateways := gatewayKey.ValueWithShadows()

				// Add gateways.
				for _, gatewayIP := range gateways {
					gateway := net.ParseIP(gatewayIP)
					if gateway == nil {
						continue
					}
					if gateway.To4() == nil {
						i.Gateway6 = gateway
					} else {
						i.Gateway4 = gateway
					}
				}

			// Add any routes specified.
			case "Route":
				// Parse the destination.
				var destination *net.IPNet
				destinationKey, _ := sec.GetKey("Destination")
				if destinationKey != nil {
					ip, ipnet, err := net.ParseCIDR(destinationKey.String())
					if err == nil {
						ipnet.IP = ip
						destination = ipnet
					}
				}
				if destination == nil {
					continue
				}

				// Parse the gateway.
				var gateway net.IP
				gatewayKey, _ := sec.GetKey("Gateway")
				if gatewayKey != nil {
					gateway = net.ParseIP(gatewayKey.String())
				}
				if gateway == nil {
					continue
				}

				// Parse the metric.
				var metric int = 256
				metricKey, _ := sec.GetKey("Metric")
				if metricKey != nil {
					metricVal, err := metricKey.Int()
					if err == nil {
						metric = metricVal
					}
				}

				// Append the route.
				i.Routes = append(i.Routes, &Route{
					Destination: destination,
					Gateway:     gateway,
					Metric:      metric,
				})
			}
		}

		// Add the interface.
		interfaces = append(interfaces, i)
	}

	return
}

// Save network config.
func (n *networkdNetwork) Save(configDir string, backupRetention int) error {
	// Get config paths.
	configPath := path.Join(configDir, n.File)
	tmpName := fmt.Sprintf("%s.tmp.%d", n.File, time.Now().UnixNano())
	tmpPath := path.Join(configDir, tmpName)

	// Try to encode/save the config.
	fd, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	_, err = n.Config.WriteTo(fd)
	fd.Close()
	if err != nil {
		return err
	}

	// Track the original file names backed up so we can prune per base.
	bases := append([]string{}, n.SubFiles...)

	// Backup existing configs.
	suffix := fmt.Sprintf(".bak.%d", time.Now().UnixNano())
	for _, file := range n.SubFiles {
		newName := file + suffix
		oldFile := path.Join(configDir, file)
		newFile := path.Join(configDir, newName)
		err := fileMove(oldFile, newFile)
		if err != nil {
			return err
		}
	}
	bakName := n.File + suffix
	bakPath := path.Join(configDir, bakName)
	err = fileMove(configPath, bakPath)
	if err != nil {
		return err
	}

	// Move new config in place.
	err = fileMove(tmpPath, configPath)
	if err != nil {
		return err
	}

	// We only have one merged file now.
	n.SubFiles = nil

	// Prune old backups beyond the retention count, per original file.
	bases = append(bases, n.File)
	for _, base := range bases {
		pruneBackups(configDir, suffixBackupMatcher(base), backupRetention)
	}

	return nil
}

func (nd *networkd) SetIfaceAddresses(_ context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) (err error) {
	for _, n := range nd.Networks {
		if n.Name != iface {
			continue
		}

		// Get existing DNS/domain config in-case different configs
		// contains them from the main section.
		var dns []string
		var domains []string
		for _, sec := range n.Config.Sections() {
			switch sec.Name() {
			// IF this is an network section, try to find addresses.
			case "Network", "Address":
				// Find the DNS.
				dnsKey, _ := sec.GetKey("DNS")
				if dnsKey != nil {
					dnsServers := dnsKey.ValueWithShadows()

					// Get the gateway.
					for _, d := range dnsServers {
						dns = append(dns, d)
					}
				}

				// Find the domains.
				domainsKey, _ := sec.GetKey("Domains")
				if domainsKey != nil {
					theseDoamins := strings.Fields(domainsKey.String())
					domains = append(domains, theseDoamins...)
				}
			}
		}

		// Delete the address sections as we'll assign add addresses
		// under the network section.
		n.Config.DeleteSection("Address")

		// Get the network section to modify it.
		sec, err := n.Config.GetSection("Network")
		if err != nil {
			return err
		}

		// Delete existing fields.
		sec.DeleteKey("Address")
		sec.DeleteKey("Gateway")
		sec.DeleteKey("DNS")
		sec.DeleteKey("Domains")

		// Update section with addresses and network configs discovered.
		for _, addr := range addrs {
			sec.NewKey("Address", addr.String())
		}
		if gateway4 != nil {
			sec.NewKey("Gateway", gateway4.String())
		}
		if gateway6 != nil {
			sec.NewKey("Gateway", gateway6.String())
		}
		for _, d := range dns {
			sec.NewKey("DNS", d)
		}
		sec.NewKey("Domains", strings.Join(domains, " "))

		// Save the network.
		err = n.Save(nd.configDir, nd.backupRetention)
		if err != nil {
			return err
		}
	}

	return nil
}

// Set static routes to interface.
func (nd *networkd) SetIfaceRoutes(_ context.Context, iface string, routes []*Route) (err error) {
	for _, n := range nd.Networks {
		if n.Name != iface {
			continue
		}

		// Delete existing routes from the config.
		n.Config.DeleteSection("Route")

		// Add routes.
		for _, route := range routes {
			sec, err := n.Config.NewSection("Route")
			if err != nil {
				return err
			}

			sec.NewKey("Destination", route.Destination.String())
			sec.NewKey("Gateway", route.Gateway.String())
			sec.NewKey("Metric", strconv.Itoa(route.Metric))
		}

		// Save the network.
		err = n.Save(nd.configDir, nd.backupRetention)
		if err != nil {
			return err
		}
	}
	return nil
}

// Set DNS servers and search domains on interface.
func (nd *networkd) SetIfaceDNS(_ context.Context, iface string, servers []net.IP, searchDomains []string) (err error) {
	for _, n := range nd.Networks {
		if n.Name != iface {
			continue
		}

		// DNS may be split across the Network and Address sections; the
		// canonical place is the Network section, so clear both and rewrite
		// the Network section.
		for _, sec := range n.Config.Sections() {
			switch sec.Name() {
			case "Network", "Address":
				sec.DeleteKey("DNS")
				sec.DeleteKey("Domains")
			}
		}

		// Get the network section to modify it.
		sec, serr := n.Config.GetSection("Network")
		if serr != nil {
			return serr
		}
		for _, d := range ipStrings(servers) {
			sec.NewKey("DNS", d)
		}
		if len(searchDomains) != 0 {
			sec.NewKey("Domains", strings.Join(searchDomains, " "))
		}

		// Save the network.
		err = n.Save(nd.configDir, nd.backupRetention)
		if err != nil {
			return err
		}
	}
	return nil
}
