package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"dario.cat/mergo"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"
)

const (
	cloudInitDefault = "/etc/cloud/cloud.cfg"
	cloudInitDir     = "/etc/cloud/cloud.cfg.d"
	cloudBaseInit    = "/curtin/network.json"
)

// Name server cvonfigurations.
type ciNameservers struct {
	Search    []string `yaml:"search,omitempty,flow" json:"search,omitempty"`
	Addresses []string `yaml:"addresses,omitempty,flow" json:"addresses,omitempty"`
}

// Common route configs.
type ciRoute struct {
	To     string `yaml:"to,omitempty" json:"to,omitempty"`
	Via    string `yaml:"via,omitempty" json:"via,omitempty"`
	Metric *int   `yaml:"metric,omitempty" json:"metric,omitempty"`
}

// Match options.
type ciMatch struct {
	Name       string `yaml:"name,omitempty" json:"name,omitempty"`
	MACAddress string `yaml:"macaddress,omitempty" json:"macaddress,omitempty"`
	Driver     string `yaml:"driver,omitempty" json:"driver,omitempty"`
}

// Common configurations on physical interfaces.
type ciPhysical struct {
	Match     ciMatch `yaml:"match,omitempty" json:"match,omitempty"`
	SetName   string  `yaml:"set-name,omitempty" json:"set-name,omitempty"`
	Wakeonlan bool    `yaml:"wakeonlan,omitempty" json:"wakeonlan,omitempty"`
}

// Common cloudinit interface configurations.
type ciInterface struct {
	Addresses      []string       `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	DHCP4          *bool          `yaml:"dhcp4,omitempty" json:"dhcp4,omitempty"`
	DHCP6          *bool          `yaml:"dhcp6,omitempty" json:"dhcp6,omitempty"`
	DHCP4Overrides map[string]any `yaml:"dhcp4-overrides,omitempty" json:"dhcp4-overrides,omitempty"`
	DHCP6Overrides map[string]any `yaml:"dhcp6-overrides,omitempty" json:"dhcp6-overrides,omitempty"`
	Gateway4       string         `yaml:"gateway4,omitempty" json:"gateway4,omitempty"`
	Gateway6       string         `yaml:"gateway6,omitempty" json:"gateway6,omitempty"`
	Nameservers    ciNameservers  `yaml:"nameservers,omitempty" json:"nameservers,omitempty"`
	MTU            int            `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	Renderer       string         `yaml:"renderer,omitempty" json:"renderer,omitempty"`
	Routes         []ciRoute      `yaml:"routes,omitempty" json:"routes,omitempty"`
	Optional       bool           `yaml:"optional,omitempty" json:"optional,omitempty"`
}

// Physical ethernet interface.
type ciEthernet struct {
	ciPhysical  `yaml:",inline" json:",inline"`
	ciInterface `yaml:",inline" json:",inline"`
}

// Bridge interface.
type ciBridgeParameters struct {
	AgeingTime   *int      `yaml:"ageing-time,omitempty" json:"ageing-time,omitempty"`
	ForwardDelay intString `yaml:"forward-delay,omitempty" json:"forward-delay,omitempty"`
	HelloTime    *int      `yaml:"hello-time,omitempty" json:"hello-time,omitempty"`
	MaxAge       *int      `yaml:"max-age,omitempty" json:"max-age,omitempty"`
	PathCost     *int      `yaml:"path-cost,omitempty" json:"path-cost,omitempty"`
	Priority     *int      `yaml:"priority,omitempty" json:"priority,omitempty"`
	STP          *bool     `yaml:"stp,omitempty" json:"stp,omitempty"`
}
type ciBridge struct {
	Interfaces  []string `yaml:"interfaces,omitempty,flow" json:"interfaces,omitempty"`
	ciInterface `yaml:",inline" json:",inline"`
	Parameters  ciBridgeParameters `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// Bond interfaces.
type ciBondParameters struct {
	Mode                  intString `yaml:"mode,omitempty" json:"mode,omitempty"`
	LACPRate              intString `yaml:"lacp-rate,omitempty" json:"lacp-rate,omitempty"`
	MIIMonitorInterval    intString `yaml:"mii-monitor-interval,omitempty" json:"mii-monitor-interval,omitempty"`
	MinLinks              *int      `yaml:"min-links,omitempty" json:"min-links,omitempty"`
	TransmitHashPolicy    string    `yaml:"transmit-hash-policy,omitempty" json:"transmit-hash-policy,omitempty"`
	ADSelect              intString `yaml:"ad-select,omitempty" json:"ad-select,omitempty"`
	AllSlavesActive       *bool     `yaml:"all-slaves-active,omitempty" json:"all-slaves-active,omitempty"`
	ARPInterval           *int      `yaml:"arp-interval,omitempty" json:"arp-interval,omitempty"`
	ARPIPTargets          []string  `yaml:"arp-ip-targets,omitempty" json:"arp-ip-targets,omitempty"`
	ARPValidate           intString `yaml:"arp-validate,omitempty" json:"arp-validate,omitempty"`
	ARPAllTargets         intString `yaml:"arp-all-targets,omitempty" json:"arp-all-targets,omitempty"`
	UpDelay               intString `yaml:"up-delay,omitempty" json:"up-delay,omitempty"`
	DownDelay             intString `yaml:"down-delay,omitempty" json:"down-delay,omitempty"`
	FailOverMACPolicy     intString `yaml:"fail-over-mac-policy,omitempty" json:"fail-over-mac-policy,omitempty"`
	GratuitousARP         *int      `yaml:"gratuitous-arp,omitempty" json:"gratuitous-arp,omitempty"`
	PacketsPerSlave       *int      `yaml:"packets-per-slave,omitempty" json:"packets-per-slave,omitempty"`
	PrimaryReselectPolicy intString `yaml:"primary-reselect-policy,omitempty" json:"primary-reselect-policy,omitempty"`
	LearnPacketInterval   *int      `yaml:"learn-packet-interval,omitempty" json:"learn-packet-interval,omitempty"`
}
type ciBond struct {
	Interfaces  []string `yaml:"interfaces,omitempty,flow" json:"interfaces,omitempty"`
	ciInterface `yaml:",inline" json:",inline"`
	Parameters  ciBondParameters `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// VLAN interface.
type ciVLAN struct {
	Id          *int   `yaml:"id,omitempty" json:"id,omitempty"`
	Link        string `yaml:"link,omitempty" json:"link,omitempty"`
	ciInterface `yaml:",inline" json:",inline"`
}

// Cloud-init network version 1 config.
type ciSubnetRoute struct {
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	Netmask     string `yaml:"netmask,omitempty" json:"netmask,omitempty"`
	Gateway     string `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	Metric      int    `yaml:"metric,omitempty" json:"metric,omitempty"`
}
type ciSubnet struct {
	Type           string          `yaml:"type" json:"type"`
	Control        intString       `yaml:"control,omitempty" json:"control,omitempty"`
	Address        string          `yaml:"address,omitempty" json:"address,omitempty"`
	Netmask        string          `yaml:"netmask,omitempty" json:"netmask,omitempty"`
	Broadcast      string          `yaml:"broadcast,omitempty" json:"broadcast,omitempty"`
	Gateway        string          `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	DNSNameservers []string        `yaml:"dns_nameservers,omitempty" json:"dns_nameservers,omitempty"`
	DNSSearch      []string        `yaml:"dns_search,omitempty" json:"dns_search,omitempty"`
	Routes         []ciSubnetRoute `yaml:"routes,omitempty" json:"routes,omitempty"`
}
type ciConfig struct {
	// Common options.
	Type       string     `yaml:"type" json:"type"`
	Name       string     `yaml:"name,omitempty" json:"name,omitempty"`
	MACAddress string     `yaml:"mac_address,omitempty" json:"mac_address,omitempty"`
	MTU        int        `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	AcceptRA   *bool      `yaml:"accept-ra,omitempty" json:"accept-ra,omitempty"`
	Subnets    []ciSubnet `yaml:"subnets,omitempty" json:"subnets,omitempty"`

	// Bridge and bond options.
	BondInterfaces   []string          `yaml:"bond_interfaces,omitempty,flow" json:"bond_interfaces,omitempty"`
	BridgeInterfaces []string          `yaml:"bridge_interfaces,omitempty,flow" json:"bridge_interfaces,omitempty"`
	Params           map[string]string `yaml:"params,omitempty" json:"params,omitempty"`

	// VLAN options.
	VLANLink string `yaml:"vlan_link,omitempty" json:"vlan_link,omitempty"`
	VLANID   int    `yaml:"vlan_id,omitempty" json:"vlan_id,omitempty"`

	// Nameserver options.
	Interface string   `yaml:"interface,omitempty" json:"interface,omitempty"`
	Addresses []string `yaml:"address,omitempty" json:"address,omitempty"`
	Search    []string `yaml:"search,omitempty" json:"search,omitempty"`

	// Route options.
	Destination string `yaml:"destination,omitempty" json:"destination,omitempty"`
	Netmask     string `yaml:"netmask,omitempty" json:"netmask,omitempty"`
	Gateway     string `yaml:"gateway,omitempty" json:"gateway,omitempty"`
	Metric      int    `yaml:"metric,omitempty" json:"metric,omitempty"`
}

// Common network structure for both v1 and v2.
type ciNetwork struct {
	Version   int                   `yaml:"version" json:"version"`
	Renderer  string                `yaml:"renderer,omitempty" json:"renderer,omitempty"`
	Ethernets map[string]ciEthernet `yaml:"ethernets,omitempty" json:"ethernets,omitempty"`
	Bridges   map[string]ciBridge   `yaml:"bridges,omitempty" json:"bridges,omitempty"`
	Bonds     map[string]ciBond     `yaml:"bonds,omitempty" json:"bonds,omitempty"`
	VLANs     map[string]ciVLAN     `yaml:"vlans,omitempty" json:"vlans,omitempty"`
	Configs   []ciConfig            `yaml:"config,omitempty" json:"config,omitempty"`
}

// The default netplan configuration structure and interface to configuring netplan.
type ciFile struct {
	Path         string
	OnlyNetwork  bool
	NetworkEncap bool
}
type cloudInit struct {
	Network         ciNetwork `yaml:"network" json:"network"`
	configFiles     []ciFile  `yaml:"-" json:"-"`
	backupRetention int       `yaml:"-" json:"-"`
}

// Find cloud-init and cloudbase-init network configurations.
func newCloudInit(backupRetention int) (ci *cloudInit, err error) {
	ci, err = newCloudInitWith(cloudInitDefault, cloudBaseInit, cloudInitDir)
	if ci != nil {
		ci.backupRetention = backupRetention
	}
	return
}
func newCloudInitWith(cloudinitFile, cloudbaseFile, cloudinitDir string) (ci *cloudInit, err error) {
	// Read data.
	var mergedConfig map[string]any
	var configFiles []ciFile
	var files []string

	// Check which base file exists.
	if _, serr := os.Stat(cloudinitFile); serr == nil {
		files = append(files, cloudinitFile)
	} else if _, serr := os.Stat(cloudbaseFile); serr == nil {
		files = append(files, cloudbaseFile)
	}

	// No files, end.
	if len(files) == 0 {
		return nil, fmt.Errorf("unable to find cloudinit config")
	}

	// Try to read the directory files.
	unsortedEntries, _ := os.ReadDir(cloudinitDir)
	entries := sortableDirEntries(unsortedEntries)
	sort.Sort(entries)

	// Add found files to list.
	for _, entry := range entries {
		// If not an cfg file, skip.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cfg") {
			continue
		}
		files = append(files, path.Join(cloudinitDir, entry.Name()))
	}

	// Parse config files.
	for _, configFile := range files {
		var data []byte
		data, err = os.ReadFile(configFile)
		if err != nil {
			return
		}

		// Setup cloud-init file info.
		var file ciFile
		file.Path = configFile

		// Parse the yaml to an map.
		var config map[string]any
		if strings.HasSuffix(configFile, ".json") {
			err = json.Unmarshal(data, &config)
			configS, ok := config["config"]
			if ok {
				version, ok := config["version"]
				if ok {
					network := make(map[string]any)
					network["config"] = configS
					network["version"] = version
					config = make(map[string]any)
					config["network"] = network
					file.NetworkEncap = true
				}

			}
		} else {
			err = yaml.Unmarshal(data, &config)
		}
		if err != nil {
			return
		}

		// Determine if this config only contains network configs.
		foundNetwork := false
		foundNonNetwork := false
		for key, value := range config {
			if key == "network" {
				// This is a network config, unless the network config
				// only contains the config disabled option.
				foundNetwork = true
				configS, ok := value.(map[string]any)
				if ok {
					// We found disabled if the config key is a string
					// with disabled.
					foundDisable := false
					configV, ok := configS["config"].(string)
					if ok && configV == "disabled" {
						foundDisable = true
					}

					// If there are other configs that are not
					// the config key, there are other configs to
					// parse.
					for keyV := range configS {
						if keyV != "config" {
							foundDisable = false
						}
					}

					// If we only found a disabled config, no network
					// config exists here.
					if foundDisable {
						foundNetwork = false
					}
				}
			} else {
				foundNonNetwork = true
			}
		}

		// If there are no network configs in this file, skip it.
		if !foundNetwork {
			continue
		}

		// If there are network configs, determine if its only network
		// and add to list of config files.
		file.OnlyNetwork = !foundNonNetwork
		configFiles = append(configFiles, file)

		// If this is the first config file read, don't merge.
		if mergedConfig == nil {
			mergedConfig = config
			continue
		}

		// Merge the configurations.
		err = mergo.Merge(&mergedConfig, config)
		if err != nil {
			return
		}
	}

	// Convert merged configs back into yaml so we can re-parse into a struct.
	mergedData, err := yaml.Marshal(mergedConfig)
	if err != nil {
		return
	}

	// Parse the cloud-init config.
	ci = new(cloudInit)
	err = yaml.Unmarshal(mergedData, ci)
	if err != nil {
		return nil, err
	}

	// If there are no ethernet configurations or configs in cloud-init, we consider the cloud-init configurations to not exist.
	if len(ci.Network.Ethernets) == 0 && len(ci.Network.Configs) == 0 {
		return nil, fmt.Errorf("no ethernet configurations in cloud-init")
	}

	// Successfully parsed, we should return.
	ci.configFiles = configFiles
	return
}

// Convert cloud-init interface to a netconfig Interface.
func (*cloudInit) ConvertInterface(name string, MAC string, config ciInterface, links []netlink.Link) *Interface {
	// Find the MAC address, starting with the list of interfaces
	// on the machine.
	var mac net.HardwareAddr
	var foundLink netlink.Link
	for _, link := range links {
		if link.Attrs().Name == name {
			mac = link.Attrs().HardwareAddr
			foundLink = link
		}
	}

	// If the MAC was not found, try parsing the config.
	if mac == nil && MAC != "" {
		mac, _ = net.ParseMAC(MAC)
	}

	// Setup interface with the name and MAC.
	i := new(Interface)
	i.Name = name
	i.MAC = mac
	i.Link = foundLink

	// Parse addresses.
	for _, addr := range config.Addresses {
		ip, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		ipnet.IP = ip
		i.Addresses = append(i.Addresses, ipnet)
	}

	// Add gateways.
	if config.Gateway4 != "" {
		i.Gateway4 = net.ParseIP(config.Gateway4)
	}
	if config.Gateway6 != "" {
		i.Gateway6 = net.ParseIP(config.Gateway6)
	}

	// Parse nameservers.
	for _, addr := range config.Nameservers.Addresses {
		if ip := net.ParseIP(addr); ip != nil {
			i.DNS = append(i.DNS, ip)
		}
	}
	i.SearchDomains = config.Nameservers.Search

	// Parse routes.
	for _, route := range config.Routes {
		dstIP, dst, err := net.ParseCIDR(route.To)
		if err != nil {
			continue
		}
		dst.IP = dstIP
		ip := net.ParseIP(route.Via)
		r := new(Route)
		r.Destination = dst
		r.Gateway = ip
		if route.Metric != nil {
			r.Metric = *route.Metric
		} else {
			r.Metric = 256
		}
		i.Routes = append(i.Routes, r)
	}
	return i
}

// Get interfaces configured.
func (ci *cloudInit) GetInterfaces() (interfaces []*Interface, err error) {
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

	// Add configs.
	for _, config := range ci.Network.Configs {
		// Skip types we cannot parse.
		switch config.Type {
		case "physical", "bond", "bridge", "vlan":
		default:
			continue
		}

		// Find the MAC address, starting with the list of interfaces
		// on the machine.
		var mac net.HardwareAddr
		var foundLink netlink.Link
		for _, link := range links {
			if link.Attrs().Name == config.Name {
				mac = link.Attrs().HardwareAddr
				foundLink = link
			}
		}

		// If we did not find the MAC address, but one is defined. Parse it.
		if mac == nil && config.MACAddress != "" {
			mac, _ = net.ParseMAC(config.MACAddress)
		}

		// Setup interface with the name and MAC.
		i := new(Interface)
		i.Name = config.Name
		i.MAC = mac
		i.Link = foundLink

		// Parse subnet configs.
		for _, subnet := range config.Subnets {
			// Add DNS servers and search domains.
			for _, dns := range subnet.DNSNameservers {
				if ip := net.ParseIP(dns); ip != nil {
					i.DNS = append(i.DNS, ip)
				}
			}
			i.SearchDomains = append(i.SearchDomains, subnet.DNSSearch...)

			// Add routes.
			for _, route := range subnet.Routes {
				r := new(Route)

				// Try and parse the destination.
				var ipnet *net.IPNet
				var ip net.IP
				if strings.Contains(route.Destination, "/") {
					ip, ipnet, err = net.ParseCIDR(route.Destination)
					if err != nil {
						continue
					}
					ipnet.IP = ip
				} else {
					ipnet = &net.IPNet{
						IP: net.ParseIP(route.Destination),
					}
					if ipnet.IP.To4() == nil {
						ipnet.Mask = net.CIDRMask(128, 128)
					} else {
						ipnet.Mask = net.CIDRMask(32, 32)
					}
				}

				// If the IP wasn't parsed, skip this route.
				if ipnet.IP == nil {
					continue
				}

				// If the netmask exists, parse and add to the destination.
				if route.Netmask != "" {
					ipMask := net.ParseIP(route.Netmask).To4()
					if ipMask == nil {
						continue
					}
					ipnet.Mask = net.IPMask(ipMask)
				}
				r.Destination = ipnet

				// Parse the gateway, requiring it.
				gateway := net.ParseIP(route.Gateway)
				if gateway == nil {
					continue
				}
				r.Gateway = gateway

				// Add the route.
				r.Metric = route.Metric
				i.Routes = append(i.Routes, r)
			}

			// Only add subnet as address if static type.
			if subnet.Type != "static" {
				continue
			}

			// Parse the address field.
			var ipnet *net.IPNet
			var ip net.IP
			if strings.Contains(subnet.Address, "/") {
				ip, ipnet, err = net.ParseCIDR(subnet.Address)
				if err != nil {
					continue
				}
				ipnet.IP = ip
			} else {
				ipnet = &net.IPNet{
					IP: net.ParseIP(subnet.Address),
				}
				if ipnet.IP.To4() == nil {
					ipnet.Mask = net.CIDRMask(128, 128)
				} else {
					ipnet.Mask = net.CIDRMask(32, 32)
				}
			}

			// If IP not parsed, skip.
			if ipnet.IP == nil {
				continue
			}

			// If subnet assigned, parse and add to address.
			if subnet.Netmask != "" {
				ipMask := net.ParseIP(subnet.Netmask).To4()
				if ipMask == nil {
					continue
				}
				ipnet.Mask = net.IPMask(ipMask)
			}

			// Add address.
			i.Addresses = append(i.Addresses, ipnet)

			// Parse the gateway.
			gateway := net.ParseIP(subnet.Gateway)
			if gateway != nil {
				if gateway.To4() == nil {
					i.Gateway6 = gateway
				} else {
					i.Gateway4 = gateway
				}
			}
		}

		// Add interface to list.
		interfaces = append(interfaces, i)
	}

	// Add ethernet interfaces to the list.
	var keys []string
	for key := range ci.Network.Ethernets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		config := ci.Network.Ethernets[name]
		// If the name is being changed in the config, use that
		// as the name.
		if config.SetName != "" {
			name = config.SetName
		}

		// Get interface.
		i := ci.ConvertInterface(name, config.Match.MACAddress, config.ciInterface, links)

		// Add the interface.
		interfaces = append(interfaces, i)
	}

	// Add Bridge interfaces to the list.
	keys = nil
	for key := range ci.Network.Bridges {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		config := ci.Network.Bridges[name]
		// Get interface.
		i := ci.ConvertInterface(name, "", config.ciInterface, links)

		// Add the interface.
		interfaces = append(interfaces, i)
	}

	// Add Bond interfaces to the list.
	keys = nil
	for key := range ci.Network.Bonds {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		config := ci.Network.Bonds[name]
		// Get interface.
		i := ci.ConvertInterface(name, "", config.ciInterface, links)

		// Add the interface.
		interfaces = append(interfaces, i)
	}

	// Add VLAN interfaces to the list.
	keys = nil
	for key := range ci.Network.VLANs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, name := range keys {
		config := ci.Network.VLANs[name]
		// Get interface.
		i := ci.ConvertInterface(name, "", config.ciInterface, links)

		// Add the interface.
		interfaces = append(interfaces, i)
	}

	return
}

// Save configurations.
func (ci *cloudInit) Save() error {
	// First we are to determine which configuration we will store the network
	// configurations to. We will call this the main config, and will consider
	// the first network only config file as the main config.
	mainConfig := ""
	for _, file := range ci.configFiles {
		if file.OnlyNetwork {
			mainConfig = file.Path
			break
		}
	}

	// If there is no network only configs, choose the first config file.
	if mainConfig == "" {
		mainConfig = ci.configFiles[0].Path
	}

	// Update all files with new configurations.
	tmpSuffix := fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	bakSuffix := fmt.Sprintf(".bak.%d", time.Now().UnixNano())
	for _, file := range ci.configFiles {
		configPath := file.Path
		configDir, configName := path.Split(configPath)
		tmpName := configName + tmpSuffix
		tmpPath := path.Join(configDir, tmpName)
		bakName := configName + bakSuffix
		bakPath := path.Join(configDir, bakName)

		// Try to encode/save the config, start by encoding to yaml,
		// then decode to a map.
		data, err := yaml.Marshal(ci)
		if err != nil {
			return err
		}
		var config map[string]any
		err = yaml.Unmarshal(data, &config)
		if err != nil {
			return err
		}

		// Decode the current config.
		data, err = os.ReadFile(configPath)
		if err != nil {
			return err
		}
		var origConfig map[string]any
		if strings.HasSuffix(configPath, ".json") {
			err = json.Unmarshal(data, &origConfig)
		} else {
			err = yaml.Unmarshal(data, &origConfig)
		}
		if err != nil {
			return err
		}

		// Update the original config with the new config.
		// On files which were not determined as the main config,
		// we will delete the network config.
		if configPath == mainConfig {
			if file.NetworkEncap {
				network := config["network"].(map[string]any)
				origConfig["config"] = network["config"]
			} else {
				origConfig["network"] = config["network"]
			}
		} else {
			if file.NetworkEncap {
				delete(origConfig, "config")
			} else {
				delete(origConfig, "network")
			}
		}

		// Save to temporary file.
		if strings.HasSuffix(configPath, ".json") {
			data, err = json.MarshalIndent(origConfig, "", "  ")
			data = append(data, '\n')
		} else {
			data, err = yaml.Marshal(origConfig)
		}
		if err != nil {
			return err
		}
		err = os.WriteFile(tmpPath, data, 0644)
		if err != nil {
			return err
		}

		// Backup original file.
		err = fileMove(configPath, bakPath)
		if err != nil {
			return err
		}

		// Move new config in place.
		err = fileMove(tmpPath, configPath)
		if err != nil {
			return err
		}

		// Prune old backups of this config file beyond the retention count.
		pruneBackups(configDir, suffixBackupMatcher(configName), ci.backupRetention)
	}

	return nil
}

// Set addresses to interface.
func (ci *cloudInit) SetIfaceAddresses(_ context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) (err error) {
	// Apply changes to v1 configs.
	for c, config := range ci.Network.Configs {
		// Skip types we cannot parse.
		switch config.Type {
		case "physical", "bond", "bridge", "vlan":
		default:
			continue
		}

		// Skip interfaces that are not the one we're updating.
		if config.Name != iface {
			continue
		}

		// Parse all routes and DNS config so we can re-add as needed.
		var routes []Route
		var dns []string
		var domains []string
		for _, subnet := range config.Subnets {
			for _, route := range subnet.Routes {
				var r Route
				// Try and parse the destination.
				var ipnet *net.IPNet
				var ip net.IP
				if strings.Contains(route.Destination, "/") {
					ip, ipnet, err = net.ParseCIDR(route.Destination)
					if err != nil {
						continue
					}
					ipnet.IP = ip
				} else {
					ipnet = &net.IPNet{
						IP: net.ParseIP(route.Destination),
					}
					if ipnet.IP.To4() == nil {
						ipnet.Mask = net.CIDRMask(128, 128)
					} else {
						ipnet.Mask = net.CIDRMask(32, 32)
					}
				}

				// If the IP wasn't parsed, skip this route.
				if ipnet.IP == nil {
					continue
				}

				// If the netmask exists, parse and add to the destination.
				if route.Netmask != "" {
					ipMask := net.ParseIP(route.Netmask).To4()
					if ipMask == nil {
						continue
					}
					ipnet.Mask = net.IPMask(ipMask)
				}
				r.Destination = ipnet

				// Parse the gateway, requiring it.
				gateway := net.ParseIP(route.Gateway)
				if gateway == nil {
					continue
				}
				r.Gateway = gateway

				// Add the route.
				r.Metric = route.Metric
				routes = append(routes, r)
			}
			for _, d := range subnet.DNSNameservers {
				found := false
				for _, d2 := range dns {
					if d2 == d {
						found = true
						break
					}
				}
				if !found {
					dns = append(dns, d)
				}
			}
			for _, d := range subnet.DNSSearch {
				found := false
				for _, d2 := range domains {
					if d2 == d {
						found = true
						break
					}
				}
				if !found {
					domains = append(domains, d)
				}
			}
		}

		// Clear existing subnets.
		config.Subnets = nil

		// Add subnets.
		for _, addr := range addrs {
			var subnet ciSubnet
			subnet.Type = "static"
			subnet.Address = addr.String()
			if addr.Contains(gateway4) {
				subnet.Gateway = gateway4.String()
			} else if addr.Contains(gateway6) {
				subnet.Gateway = gateway6.String()
			}

			// Add back DNS config.
			subnet.DNSNameservers = dns
			subnet.DNSSearch = domains

			// Add all pertaining routes.
			for {
				foundRoute := false
				for r, route := range routes {
					if addr.Contains(route.Gateway) {
						foundRoute = true
						subnet.Routes = append(subnet.Routes, ciSubnetRoute{
							Destination: route.Destination.String(),
							Gateway:     route.Gateway.String(),
							Metric:      route.Metric,
						})
						routes = append(routes[:r], routes[r+1:]...)
						break
					}
				}
				if !foundRoute {
					break
				}
			}

			// Add subnet.
			config.Subnets = append(config.Subnets, subnet)
		}

		// Add stray routes to the first subnet.
		if len(routes) != 0 && len(config.Subnets) != 0 {
			for _, route := range routes {
				config.Subnets[0].Routes = append(config.Subnets[0].Routes, ciSubnetRoute{
					Destination: route.Destination.String(),
					Gateway:     route.Gateway.String(),
					Metric:      route.Metric,
				})
			}
		}

		// Update the config.
		ci.Network.Configs[c] = config
	}

	// Check ethernet interfaces.
	for name, config := range ci.Network.Ethernets {
		// If the name is being changed in the config, use that
		// as the name.
		ifName := name
		if config.SetName != "" {
			ifName = config.SetName
		}

		// If this is not the interface we're updating addresses on.
		if ifName != iface {
			continue
		}

		// Re-configure with specified addresses.
		config.Addresses = nil
		for _, addr := range addrs {
			config.Addresses = append(config.Addresses, addr.String())
		}
		if gateway4 == nil {
			config.Gateway4 = ""
		} else {
			config.Gateway4 = gateway4.String()
		}
		if gateway6 == nil {
			config.Gateway6 = ""
		} else {
			config.Gateway6 = gateway6.String()
		}
		ci.Network.Ethernets[name] = config
	}

	// Check bridges.
	{
		config, ok := ci.Network.Bridges[iface]
		if ok {
			// Re-configure with specified addresses.
			config.Addresses = nil
			for _, addr := range addrs {
				config.Addresses = append(config.Addresses, addr.String())
			}
			if gateway4 == nil {
				config.Gateway4 = ""
			} else {
				config.Gateway4 = gateway4.String()
			}
			if gateway6 == nil {
				config.Gateway6 = ""
			} else {
				config.Gateway6 = gateway6.String()
			}
			ci.Network.Bridges[iface] = config
		}
	}

	// Check bonds.
	{
		config, ok := ci.Network.Bonds[iface]
		if ok {
			// Re-configure with specified addresses.
			config.Addresses = nil
			for _, addr := range addrs {
				config.Addresses = append(config.Addresses, addr.String())
			}
			if gateway4 == nil {
				config.Gateway4 = ""
			} else {
				config.Gateway4 = gateway4.String()
			}
			if gateway6 == nil {
				config.Gateway6 = ""
			} else {
				config.Gateway6 = gateway6.String()
			}
			ci.Network.Bonds[iface] = config
		}
	}

	// Check VLAN interfaces.
	{
		config, ok := ci.Network.VLANs[iface]
		if ok {
			// Re-configure with specified addresses.
			config.Addresses = nil
			for _, addr := range addrs {
				config.Addresses = append(config.Addresses, addr.String())
			}
			if gateway4 == nil {
				config.Gateway4 = ""
			} else {
				config.Gateway4 = gateway4.String()
			}
			if gateway6 == nil {
				config.Gateway6 = ""
			} else {
				config.Gateway6 = gateway6.String()
			}
			ci.Network.VLANs[iface] = config
		}
	}

	// Try to save changes.
	err = ci.Save()
	return
}

// Set static routes to interface.
func (ci *cloudInit) SetIfaceRoutes(_ context.Context, iface string, routes []*Route) (err error) {
	// Apply changes to v1 configs.
	for c, config := range ci.Network.Configs {
		// Skip types we cannot parse.
		switch config.Type {
		case "physical", "bond", "bridge", "vlan":
		default:
			continue
		}

		// Skip interfaces that are not the one we're updating.
		if config.Name != iface {
			continue
		}

		if len(config.Subnets) == 0 {
			return fmt.Errorf("no subnets on interface")
		}

		// Remove existing routes, and parse destination.
		subnetMap := make(map[int]*net.IPNet)
		for s, subnet := range config.Subnets {
			config.Subnets[s].Routes = nil

			// Only add subnet as address if static type.
			if subnet.Type != "static" {
				continue
			}

			// Parse the address field.
			var ipnet *net.IPNet
			var ip net.IP
			if strings.Contains(subnet.Address, "/") {
				ip, ipnet, err = net.ParseCIDR(subnet.Address)
				if err != nil {
					continue
				}
				ipnet.IP = ip
			} else {
				ipnet = &net.IPNet{
					IP: net.ParseIP(subnet.Address),
				}
				if ipnet.IP.To4() == nil {
					ipnet.Mask = net.CIDRMask(128, 128)
				} else {
					ipnet.Mask = net.CIDRMask(32, 32)
				}
			}

			// If IP not parsed, skip.
			if ipnet.IP == nil {
				continue
			}

			// If subnet assigned, parse and add to address.
			if subnet.Netmask != "" {
				ipMask := net.ParseIP(subnet.Netmask).To4()
				if ipMask == nil {
					continue
				}
				ipnet.Mask = net.IPMask(ipMask)
			}

			// Add to map.
			subnetMap[s] = ipnet
		}

		// Add each route accordingly.
		for _, route := range routes {
			// Find subnet to assign route, defaulting to 0.
			idx := 0
			for s, ipnet := range subnetMap {
				if ipnet.Contains(route.Gateway) {
					idx = s
					break
				}
			}

			// Add route.
			var r ciSubnetRoute
			r.Destination = route.Destination.String()
			r.Gateway = route.Gateway.String()
			r.Metric = route.Metric
			config.Subnets[idx].Routes = append(config.Subnets[idx].Routes, r)
		}

		// Update configs.
		ci.Network.Configs[c] = config
	}

	// Check ethernet interfaces.
	for name, config := range ci.Network.Ethernets {
		// If the name is being changed in the config, use that
		// as the name.
		ifName := name
		if config.SetName != "" {
			ifName = config.SetName
		}

		// If this is not the interface we're updating routes on.
		if ifName != iface {
			continue
		}

		// Re-configure with specified routes.
		config.Routes = nil
		for _, route := range routes {
			config.Routes = append(config.Routes, ciRoute{
				To:     route.Destination.String(),
				Via:    route.Gateway.String(),
				Metric: &route.Metric,
			})
		}
		ci.Network.Ethernets[name] = config
	}

	// Check bridges.
	{
		config, ok := ci.Network.Bridges[iface]
		if ok {
			// Re-configure with specified routes.
			config.Routes = nil
			for _, route := range routes {
				config.Routes = append(config.Routes, ciRoute{
					To:     route.Destination.String(),
					Via:    route.Gateway.String(),
					Metric: &route.Metric,
				})
			}
			ci.Network.Bridges[iface] = config
		}
	}

	// Check bonds.
	{
		config, ok := ci.Network.Bonds[iface]
		if ok {
			// Re-configure with specified routes.
			config.Routes = nil
			for _, route := range routes {
				config.Routes = append(config.Routes, ciRoute{
					To:     route.Destination.String(),
					Via:    route.Gateway.String(),
					Metric: &route.Metric,
				})
			}
			ci.Network.Bonds[iface] = config
		}
	}

	// Check VLAN interfaces.
	{
		config, ok := ci.Network.VLANs[iface]
		if ok {
			// Re-configure with specified routes.
			config.Routes = nil
			for _, route := range routes {
				config.Routes = append(config.Routes, ciRoute{
					To:     route.Destination.String(),
					Via:    route.Gateway.String(),
					Metric: &route.Metric,
				})
			}
			ci.Network.VLANs[iface] = config
		}
	}

	// Try to save changes.
	err = ci.Save()
	return
}

// Set DNS servers and search domains on interface.
func (ci *cloudInit) SetIfaceDNS(_ context.Context, iface string, servers []net.IP, searchDomains []string) (err error) {
	dnsStrings := ipStrings(servers)
	nameservers := ciNameservers{
		Search:    searchDomains,
		Addresses: dnsStrings,
	}

	// Apply changes to v1 configs, where DNS lives on each subnet.
	for c, config := range ci.Network.Configs {
		switch config.Type {
		case "physical", "bond", "bridge", "vlan":
		default:
			continue
		}
		if config.Name != iface {
			continue
		}
		for s := range config.Subnets {
			config.Subnets[s].DNSNameservers = dnsStrings
			config.Subnets[s].DNSSearch = searchDomains
		}
		ci.Network.Configs[c] = config
	}

	// Apply changes to v2 ethernet interfaces.
	for name, config := range ci.Network.Ethernets {
		ifName := name
		if config.SetName != "" {
			ifName = config.SetName
		}
		if ifName != iface {
			continue
		}
		config.Nameservers = nameservers
		ci.Network.Ethernets[name] = config
	}

	// Apply changes to v2 bridges, bonds, and VLANs.
	if config, ok := ci.Network.Bridges[iface]; ok {
		config.Nameservers = nameservers
		ci.Network.Bridges[iface] = config
	}
	if config, ok := ci.Network.Bonds[iface]; ok {
		config.Nameservers = nameservers
		ci.Network.Bonds[iface] = config
	}
	if config, ok := ci.Network.VLANs[iface]; ok {
		config.Nameservers = nameservers
		ci.Network.VLANs[iface] = config
	}

	// Try to save changes.
	err = ci.Save()
	return
}
