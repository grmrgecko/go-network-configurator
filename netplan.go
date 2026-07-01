package netconfig

import (
	"context"
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

// Name server cvonfigurations.
type npNameservers struct {
	Search    []string `yaml:"search,omitempty,flow"`
	Addresses []string `yaml:"addresses,omitempty,flow"`
}

// Route configurations.
type npRoute struct {
	From   string `yaml:"from,omitempty"`
	OnLink *bool  `yaml:"on-link,omitempty"`
	Scope  string `yaml:"scope,omitempty"`
	Table  *int   `yaml:"table,omitempty"`
	To     string `yaml:"to,omitempty"`
	Type   string `yaml:"type,omitempty"`
	Via    string `yaml:"via,omitempty"`
	Metric *int   `yaml:"metric,omitempty"`
}
type npRoutePolicy struct {
	From          string `yaml:"from,omitempty"`
	Mark          *int   `yaml:"mark,omitempty"`
	Priority      *int   `yaml:"priority,omitempty"`
	Table         *int   `yaml:"table,omitempty"`
	To            string `yaml:"to,omitempty"`
	TypeOfService *int   `yaml:"type-of-service,omitempty"`
}

// Match options.
type npMatch struct {
	Name       string `yaml:"name,omitempty"`
	MACAddress string `yaml:"macaddress,omitempty"`
	Driver     string `yaml:"driver,omitempty"`
}

// Common configurations on physical interfaces.
type npPhysical struct {
	Match     npMatch `yaml:"match,omitempty"`
	SetName   string  `yaml:"set-name,omitempty"`
	Wakeonlan bool    `yaml:"wakeonlan,omitempty"`
}

// Common netplan interface configurations.
type npInterface struct {
	AcceptRA       *bool           `yaml:"accept-ra,omitempty"`
	Addresses      []string        `yaml:"addresses,omitempty"`
	Critical       bool            `yaml:"critical,omitempty"`
	DHCP4          *bool           `yaml:"dhcp4,omitempty"`
	DHCP6          *bool           `yaml:"dhcp6,omitempty"`
	DHCP4Overrides map[string]any  `yaml:"dhcp4-overrides,omitempty"`
	DHCP6Overrides map[string]any  `yaml:"dhcp6-overrides,omitempty"`
	DHCPIdentifier string          `yaml:"dhcp-identifier,omitempty"`
	Gateway4       string          `yaml:"gateway4,omitempty"`
	Gateway6       string          `yaml:"gateway6,omitempty"`
	Nameservers    npNameservers   `yaml:"nameservers,omitempty"`
	MACAddress     string          `yaml:"macaddress,omitempty"`
	MTU            int             `yaml:"mtu,omitempty"`
	Renderer       string          `yaml:"renderer,omitempty"`
	Routes         []npRoute       `yaml:"routes,omitempty"`
	RoutingPolicy  []npRoutePolicy `yaml:"routing-policy,omitempty"`
	Optional       bool            `yaml:"optional,omitempty"`

	// Configure the link-local addresses to bring up. Valid options are
	// "ipv4" and "ipv6". According to the netplan reference, netplan will
	// only bring up ipv6 addresses if *no* link-local attribute is
	// specified. On the other hand, if an empty link-local attribute is
	// specified, this instructs netplan not to bring any ipv4/ipv6 address
	// up.
	LinkLocal *[]string `yaml:"link-local,omitempty"`

	// According to the netplan examples, this section typically includes
	// some OVS-specific configuration bits. However, MAAS may just
	// include an empty block to indicate the presence of an OVS-managed
	// bridge (LP1942328). As a workaround, we make this an optional map
	// so we can tell whether it is present (but empty) vs not being
	// present.
	//
	// See: https://github.com/canonical/netplan/blob/main/examples/openvswitch.yaml
	OVSParameters *map[string]interface{} `yaml:"openvswitch,omitempty"`
}

// dhcpState reports whether each family's DHCP client is enabled. An absent
// key means netplan's default, which is off.
func (c *npInterface) dhcpState() (dhcp4, dhcp6 bool) {
	return c.DHCP4 != nil && *c.DHCP4, c.DHCP6 != nil && *c.DHCP6
}

// setDHCP records the requested DHCP client state for both families. Disabling
// a family drops its dhcp4-overrides/dhcp6-overrides, which netplan only reads
// while that client runs. A family being disabled that was already absent is
// left absent rather than written out as false, so reading and rewriting a
// config that never mentioned DHCP does not churn it.
func (c *npInterface) setDHCP(dhcp4, dhcp6 bool) {
	if dhcp4 || c.DHCP4 != nil {
		c.DHCP4 = boolPtr(dhcp4)
	}
	if !dhcp4 {
		c.DHCP4Overrides = nil
	}
	if dhcp6 || c.DHCP6 != nil {
		c.DHCP6 = boolPtr(dhcp6)
	}
	if !dhcp6 {
		c.DHCP6Overrides = nil
	}
}

// Physical ethernet configurations.
type npEthernet struct {
	npPhysical  `yaml:",inline"`
	npInterface `yaml:",inline"`
}

// Wifi configurations.
type npAccessPoint struct {
	Password string `yaml:"password,omitempty"`
	Mode     string `yaml:"mode,omitempty"`
	Channel  int    `yaml:"channel,omitempty"`
}
type npWifi struct {
	npPhysical   `yaml:",inline"`
	AccessPoints map[string]npAccessPoint `yaml:"access-points,omitempty"`
	npInterface  `yaml:",inline"`
}

// Bridge interface configurations.
type npBridgeParameters struct {
	AgeingTime   *int           `yaml:"ageing-time,omitempty"`
	ForwardDelay intString      `yaml:"forward-delay,omitempty"`
	HelloTime    *int           `yaml:"hello-time,omitempty"`
	MaxAge       *int           `yaml:"max-age,omitempty"`
	PathCost     map[string]int `yaml:"path-cost,omitempty"`
	PortPriority map[string]int `yaml:"port-priority,omitempty"`
	Priority     *int           `yaml:"priority,omitempty"`
	STP          *bool          `yaml:"stp,omitempty"`
}
type npBridge struct {
	Interfaces  []string `yaml:"interfaces,omitempty,flow"`
	npInterface `yaml:",inline"`
	Parameters  npBridgeParameters `yaml:"parameters,omitempty"`
}

// Bond interface configurations.
type npBondParameters struct {
	Mode               intString `yaml:"mode,omitempty"`
	LACPRate           intString `yaml:"lacp-rate,omitempty"`
	MIIMonitorInterval intString `yaml:"mii-monitor-interval,omitempty"`
	MinLinks           *int      `yaml:"min-links,omitempty"`
	TransmitHashPolicy string    `yaml:"transmit-hash-policy,omitempty"`
	ADSelect           intString `yaml:"ad-select,omitempty"`
	AllSlavesActive    *bool     `yaml:"all-slaves-active,omitempty"`
	ARPInterval        *int      `yaml:"arp-interval,omitempty"`
	ARPIPTargets       []string  `yaml:"arp-ip-targets,omitempty"`
	ARPValidate        intString `yaml:"arp-validate,omitempty"`
	ARPAllTargets      intString `yaml:"arp-all-targets,omitempty"`
	UpDelay            intString `yaml:"up-delay,omitempty"`
	DownDelay          intString `yaml:"down-delay,omitempty"`
	FailOverMACPolicy  intString `yaml:"fail-over-mac-policy,omitempty"`
	// Netplan misspelled this and retained it along with the corrected spelling.
	GratuitousARPLegacy   *int      `yaml:"gratuitious-arp,omitempty"` // nolint: misspell
	GratuitousARP         *int      `yaml:"gratuitous-arp,omitempty"`
	PacketsPerSlave       *int      `yaml:"packets-per-slave,omitempty"`
	PrimaryReselectPolicy intString `yaml:"primary-reselect-policy,omitempty"`
	ResendIGMP            *int      `yaml:"resend-igmp,omitempty"`
	// bonding.txt says that this can be a value from 1-0x7fffffff, should we be forcing it to be a hex value?
	LearnPacketInterval *int   `yaml:"learn-packet-interval,omitempty"`
	Primary             string `yaml:"primary,omitempty"`
}
type npBond struct {
	Interfaces  []string `yaml:"interfaces,omitempty,flow"`
	npInterface `yaml:",inline"`
	Parameters  npBondParameters `yaml:"parameters,omitempty"`
}

// VLAN interface configurations.
type npVLAN struct {
	Id          *int   `yaml:"id,omitempty"`
	Link        string `yaml:"link,omitempty"`
	npInterface `yaml:",inline"`
}

// Common netplan network configs.
type npNetwork struct {
	Version   intString             `yaml:"version"`
	Renderer  string                `yaml:"renderer,omitempty"`
	Ethernets map[string]npEthernet `yaml:"ethernets,omitempty"`
	Wifis     map[string]npWifi     `yaml:"wifis,omitempty"`
	Bridges   map[string]npBridge   `yaml:"bridges,omitempty"`
	Bonds     map[string]npBond     `yaml:"bonds,omitempty"`
	VLANs     map[string]npVLAN     `yaml:"vlans,omitempty"`
	Routes    []npRoute             `yaml:"routes,omitempty"`
}

// The default netplan configuration structure and interface to configuring netplan.
type npConfig struct {
	Network npNetwork `yaml:"network"`
	file    string    `yaml:"-"`
	empty   bool      `yaml:"-"`
	// dirty marks that a Set* call actually modified this file's in-memory
	// config during the current operation. Save only rewrites/backs up dirty
	// files, so files nobody touched (including legitimately empty netplan
	// fragments that were never merged away) are left untouched on disk.
	dirty bool `yaml:"-"`
}

type netplan struct {
	configs         []*npConfig `yaml:"-"`
	configDir       string      `yaml:"-"`
	backupRetention int
}

// Verify netplan exists, and try parsing its configurations. The `netplan info`
// probe is bound to ctx so a wedged netplan cannot stall construction.
func newNetplan(ctx context.Context, backupRetention int) (np *netplan, err error) {
	// Calling netplan info will verify netplan is on the machine and working,
	// not merely installed.
	_, err = runCommand(ctx, "netplan", "info")
	if err != nil {
		return
	}

	// Try to parse the netplan configurations. /etc/netplan is the durable,
	// admin-facing source of truth and is tried first so persisted changes
	// actually survive a reboot; /run/netplan is a volatile tmpfs directory
	// that netplan also honors (e.g. "netplan try") and is only used as a
	// fallback, otherwise a host with any file in /run/netplan would have its
	// real /etc/netplan configuration silently ignored.
	np, err = readNetplanConfigDirectory("/etc/netplan")
	if err != nil {
		np, err = readNetplanConfigDirectory("/run/netplan")
		if err != nil {
			np, err = readNetplanConfigDirectory("/lib/netplan")
		}
	}
	if np != nil {
		np.backupRetention = backupRetention
	}
	return
}

// Read an netplan configuration directory for netplan configuration files.
func readNetplanConfigDirectory(dirPath string) (np *netplan, err error) {
	// Try to read the directory files.
	unsortedEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}

	// Sort by name.
	entries := sortableDirEntries(unsortedEntries)
	sort.Sort(entries)

	// Temporary struct to store unparsed configs.
	type npConfigFile struct {
		data  map[string]any
		file  string
		empty bool
		// dirty marks that this file's in-memory data no longer matches what
		// is on disk because a duplicate key was merged into (or out of) it
		// during parsing, so it must be rewritten on the next Save even if no
		// Set* call ends up touching an interface still contained in it.
		dirty bool
	}
	var configs []*npConfigFile
	configTypes := []string{"ethernets", "wifis", "bridges", "bonds", "vlans", "routes"}

	// Read each yaml file and merge into a single config.
	for _, entry := range entries {
		// If not an yaml file, skip.
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		config := &npConfigFile{
			file:  entry.Name(),
			empty: false,
		}

		// Read the bytes from the file.
		configPath := path.Join(dirPath, entry.Name())
		var data []byte
		data, err = os.ReadFile(configPath)
		if err != nil {
			return
		}

		// Parse the yaml to an map.
		err = yaml.Unmarshal(data, &config.data)
		if err != nil {
			return
		}

		// Check if prior configs have same network configs and merge.
		configCount := 0
		network, ok := config.data["network"].(map[string]any)
		if !ok {
			goto addConfig
		}

		// Merge types with prior configs.
		for _, t := range configTypes {
			// First get the config type.
			c, ok := network[t].(map[string]any)
			if !ok {
				continue
			}

			// Loop through all prior parsed configs,
			// and find ones that has same type.
			for _, thisConfig := range configs {
				// If empty, there is no config so skip.
				if thisConfig.empty {
					continue
				}

				// Try and get the config type from this config.
				thisC, ok := thisConfig.data["network"].(map[string]any)[t].(map[string]any)
				if !ok {
					continue
				}

				// Find entries in this config which match the current config.
				for key, _ := range thisC {
					// Find and if not found, skip.
					k, ok := c[key].(map[string]any)
					if !ok {
						continue
					}
					thisK := thisC[key].(map[string]any)

					// This config contains a key from the current.
					// We need to merge.
					err = mergo.Merge(&thisK, k)
					if err != nil {
						return
					}

					// Update the previously parsed data with merged data.
					thisConfig.data["network"].(map[string]any)[t].(map[string]any)[key] = thisK
					thisConfig.dirty = true

					// Delete the config from the current config.
					delete(config.data["network"].(map[string]any)[t].(map[string]any), key)
					delete(network[t].(map[string]any), key)
					config.dirty = true
				}
			}
		}

		// Count number of configs to determine if file is empty.
		for _, t := range configTypes {
			// First get the config type.
			c, ok := network[t].(map[string]any)
			if !ok {
				continue
			}
			configCount += len(c)
		}
	addConfig:
		routes, ok := config.data["routes"].([]any)
		if ok {
			configCount += len(routes)
		}
		config.empty = configCount == 0

		// Add config to slice of configs.
		configs = append(configs, config)
	}

	// No config when no configs.
	if len(configs) == 0 {
		return nil, fmt.Errorf("no netplan configurations found")
	}
	err = nil

	// Build the netplan data.
	np = new(netplan)
	np.configDir = dirPath
	for _, config := range configs {
		// Convert config data back into yaml so we can re-parse into a struct.
		data, err := yaml.Marshal(config.data)
		if err != nil {
			return nil, err
		}

		// Parse the netplan config.
		cfg := new(npConfig)
		err = yaml.Unmarshal(data, cfg)
		if err != nil {
			return nil, err
		}

		// Successfully parsed, append to the configs slice.
		cfg.file = config.file
		cfg.dirty = config.dirty
		cfg.empty = config.empty
		np.configs = append(np.configs, cfg)
	}
	return
}

// Convert netplan interface to a netconfig Interface.
func (*netplan) ConvertInterface(name string, config npInterface, links []netlink.Link) *Interface {
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
	if mac == nil && config.MACAddress != "" {
		mac, _ = net.ParseMAC(config.MACAddress)
	}

	// Setup interface with the name and MAC.
	i := new(Interface)
	i.Name = name
	i.MAC = mac
	i.Link = foundLink
	i.DHCP4, i.DHCP6 = config.dhcpState()

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
func (np *netplan) GetInterfaces() (interfaces []*Interface, err error) {
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

	// Add each config.
	for _, c := range np.configs {
		if c.empty {
			continue
		}

		// Add ethernet interfaces to the list.
		var keys []string
		for key := range c.Network.Ethernets {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			config := c.Network.Ethernets[name]
			// If the name is being changed in the config, use that
			// as the name.
			if config.SetName != "" {
				name = config.SetName
			}

			// Update the config MAC to the match MAC.
			if config.MACAddress == "" {
				config.MACAddress = config.Match.MACAddress
			}

			// Get interface.
			i := np.ConvertInterface(name, config.npInterface, links)

			// Add the interface.
			interfaces = append(interfaces, i)
		}

		// Add Wifi interfaces to the list.
		keys = nil
		for key := range c.Network.Wifis {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			config := c.Network.Wifis[name]
			// If the name is being changed in the config, use that
			// as the name.
			if config.SetName != "" {
				name = config.SetName
			}

			// Update the config MAC to the match MAC.
			if config.MACAddress == "" {
				config.MACAddress = config.Match.MACAddress
			}

			// Get interface.
			i := np.ConvertInterface(name, config.npInterface, links)

			// Add the interface.
			interfaces = append(interfaces, i)
		}

		// Add Bridge interfaces to the list.
		keys = nil
		for key := range c.Network.Bridges {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			config := c.Network.Bridges[name]
			// Get interface.
			i := np.ConvertInterface(name, config.npInterface, links)

			// Add the interface.
			interfaces = append(interfaces, i)
		}

		// Add Bond interfaces to the list.
		keys = nil
		for key := range c.Network.Bonds {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			config := c.Network.Bonds[name]
			// Get interface.
			i := np.ConvertInterface(name, config.npInterface, links)

			// Add the interface.
			interfaces = append(interfaces, i)
		}

		// Add VLAN interfaces to the list.
		keys = nil
		for key := range c.Network.VLANs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, name := range keys {
			config := c.Network.VLANs[name]
			// Get interface.
			i := np.ConvertInterface(name, config.npInterface, links)

			// Add the interface.
			interfaces = append(interfaces, i)
		}
	}

	return
}

// Save configurations.
func (np *netplan) Save() error {
	// Update each configuration file that was actually touched by this
	// operation. Configs nobody modified are left alone on disk, so an
	// unrelated legitimately-empty netplan fragment is never backed up and
	// removed as a side effect of changing a different interface.
	for _, config := range np.configs {
		if !config.dirty {
			continue
		}

		// Get config paths.
		configPath := path.Join(np.configDir, config.file)
		tmpName := fmt.Sprintf("%s.tmp.%d", config.file, time.Now().UnixNano())
		tmpPath := path.Join(np.configDir, tmpName)
		bakupName := fmt.Sprintf("%s.bak.%d", config.file, time.Now().UnixNano())
		bakupPath := path.Join(np.configDir, bakupName)

		// Only save if not empty.
		if !config.empty {
			// Try to encode/save the config.
			data, err := yaml.Marshal(config)
			if err != nil {
				return err
			}
			err = os.WriteFile(tmpPath, data, 0644)
			if err != nil {
				return err
			}
		}

		// Backup old config.
		err := fileMove(configPath, bakupPath)
		if err != nil {
			return err
		}

		// Move new config in place.
		if !config.empty {
			// Move new config in place.
			err = fileMove(tmpPath, configPath)
			if err != nil {
				return err
			}
		}

		// Prune old backups of this config file beyond the retention count.
		pruneBackups(np.configDir, suffixBackupMatcher(config.file), np.backupRetention)

		// The file on disk now matches this config's in-memory state, so it
		// does not need rewriting again until something else marks it dirty.
		// Configs that turned out empty are left dirty so the cleanup pass
		// below still notices they were just removed from disk.
		if !config.empty {
			config.dirty = false
		}
	}

	// Now that touched configurations were updated, drop the ones we just
	// emptied out and removed from disk above. Configs that were already
	// empty but untouched this call were left on disk, so they stay tracked.
	// Rebuild the slice rather than deleting in place while ranging over it,
	// which would shift the backing array under the loop and skip or drop the
	// wrong entries when more than one config was emptied.
	kept := np.configs[:0]
	for _, config := range np.configs {
		if config.dirty && config.empty {
			continue
		}
		kept = append(kept, config)
	}
	np.configs = kept

	return nil
}

// Set addresses to interface.
func (np *netplan) SetIfaceAddresses(_ context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) (err error) {
	// Update each config.
	for _, c := range np.configs {
		if c.empty {
			continue
		}

		// Check ethernet interfaces.
		for name, config := range c.Network.Ethernets {
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
			c.dirty = true

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
			c.Network.Ethernets[name] = config
		}

		// Check Wifi interfaces.
		for name, config := range c.Network.Wifis {
			// If the name is being changed in the config, use that
			// as the name.
			ifName := name
			if config.SetName != "" {
				ifName = config.SetName
			}

			// If this is the interface we're updating addresses on.
			if ifName != iface {
				continue
			}
			c.dirty = true

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
			c.Network.Wifis[name] = config
		}

		// Check bridges.
		{
			config, ok := c.Network.Bridges[iface]
			if ok {
				c.dirty = true
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
				c.Network.Bridges[iface] = config
			}
		}

		// Check bonds.
		{
			config, ok := c.Network.Bonds[iface]
			if ok {
				c.dirty = true
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
				c.Network.Bonds[iface] = config
			}
		}

		// Check VLAN interfaces.
		{
			config, ok := c.Network.VLANs[iface]
			if ok {
				c.dirty = true
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
				c.Network.VLANs[iface] = config
			}
		}
	}

	// Try to save changes.
	err = np.Save()
	return
}

// Set the DHCP client state on an interface.
func (np *netplan) SetIfaceDHCP(_ context.Context, iface string, dhcp4, dhcp6 bool) (err error) {
	// Update each config.
	for _, c := range np.configs {
		if c.empty {
			continue
		}

		// Check ethernet interfaces.
		for name, config := range c.Network.Ethernets {
			// If the name is being changed in the config, use that as the name.
			ifName := name
			if config.SetName != "" {
				ifName = config.SetName
			}
			if ifName != iface {
				continue
			}
			c.dirty = true
			config.setDHCP(dhcp4, dhcp6)
			c.Network.Ethernets[name] = config
		}

		// Check Wifi interfaces.
		for name, config := range c.Network.Wifis {
			ifName := name
			if config.SetName != "" {
				ifName = config.SetName
			}
			if ifName != iface {
				continue
			}
			c.dirty = true
			config.setDHCP(dhcp4, dhcp6)
			c.Network.Wifis[name] = config
		}

		// Check bridges.
		if config, ok := c.Network.Bridges[iface]; ok {
			c.dirty = true
			config.setDHCP(dhcp4, dhcp6)
			c.Network.Bridges[iface] = config
		}

		// Check bonds.
		if config, ok := c.Network.Bonds[iface]; ok {
			c.dirty = true
			config.setDHCP(dhcp4, dhcp6)
			c.Network.Bonds[iface] = config
		}

		// Check VLAN interfaces.
		if config, ok := c.Network.VLANs[iface]; ok {
			c.dirty = true
			config.setDHCP(dhcp4, dhcp6)
			c.Network.VLANs[iface] = config
		}
	}

	// Try to save changes.
	err = np.Save()
	return
}

// renewDHCP makes netplan realize the configuration that was just written, so a
// newly enabled DHCP client starts and acquires a lease. `netplan apply` is the
// only supported way in; it reconciles every interface, not just this one, and
// so is a no-op for the interfaces whose configuration did not change.
func (np *netplan) renewDHCP(ctx context.Context, _ string) error {
	_, err := runCommand(ctx, "netplan", "apply")
	return err
}

// Set static routes to interface.
func (np *netplan) SetIfaceRoutes(_ context.Context, iface string, routes []*Route) (err error) {
	// Update each config.
	for _, c := range np.configs {
		if c.empty {
			continue
		}

		// Check ethernet interfaces.
		for name, config := range c.Network.Ethernets {
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
			c.dirty = true

			// Re-configure with specified routes.
			config.Routes = nil
			for _, route := range routes {
				config.Routes = append(config.Routes, npRoute{
					To:     route.Destination.String(),
					Via:    route.Gateway.String(),
					Metric: &route.Metric,
				})
			}
			c.Network.Ethernets[name] = config
		}

		// Check Wifi interfaces.
		for name, config := range c.Network.Wifis {
			// If the name is being changed in the config, use that
			// as the name.
			ifName := name
			if config.SetName != "" {
				ifName = config.SetName
			}

			// If this is the interface we're updating routes on.
			if ifName != iface {
				continue
			}
			c.dirty = true

			// Re-configure with specified routes.
			config.Routes = nil
			for _, route := range routes {
				config.Routes = append(config.Routes, npRoute{
					To:     route.Destination.String(),
					Via:    route.Gateway.String(),
					Metric: &route.Metric,
				})
			}
			c.Network.Wifis[name] = config
		}

		// Check bridges.
		{
			config, ok := c.Network.Bridges[iface]
			if ok {
				c.dirty = true
				// Re-configure with specified routes.
				config.Routes = nil
				for _, route := range routes {
					config.Routes = append(config.Routes, npRoute{
						To:     route.Destination.String(),
						Via:    route.Gateway.String(),
						Metric: &route.Metric,
					})
				}
				c.Network.Bridges[iface] = config
			}
		}

		// Check bonds.
		{
			config, ok := c.Network.Bonds[iface]
			if ok {
				c.dirty = true
				// Re-configure with specified routes.
				config.Routes = nil
				for _, route := range routes {
					config.Routes = append(config.Routes, npRoute{
						To:     route.Destination.String(),
						Via:    route.Gateway.String(),
						Metric: &route.Metric,
					})
				}
				c.Network.Bonds[iface] = config
			}
		}

		// Check VLAN interfaces.
		{
			config, ok := c.Network.VLANs[iface]
			if ok {
				c.dirty = true
				// Re-configure with specified routes.
				config.Routes = nil
				for _, route := range routes {
					config.Routes = append(config.Routes, npRoute{
						To:     route.Destination.String(),
						Via:    route.Gateway.String(),
						Metric: &route.Metric,
					})
				}
				c.Network.VLANs[iface] = config
			}
		}
	}

	// Try to save changes.
	err = np.Save()
	return
}

// Set DNS servers and search domains on interface.
func (np *netplan) SetIfaceDNS(_ context.Context, iface string, servers []net.IP, searchDomains []string) (err error) {
	nameservers := npNameservers{
		Search:    searchDomains,
		Addresses: ipStrings(servers),
	}

	// Update each config.
	for _, c := range np.configs {
		if c.empty {
			continue
		}

		// Check ethernet interfaces.
		for name, config := range c.Network.Ethernets {
			ifName := name
			if config.SetName != "" {
				ifName = config.SetName
			}
			if ifName != iface {
				continue
			}
			c.dirty = true
			config.Nameservers = nameservers
			c.Network.Ethernets[name] = config
		}

		// Check Wifi interfaces.
		for name, config := range c.Network.Wifis {
			ifName := name
			if config.SetName != "" {
				ifName = config.SetName
			}
			if ifName != iface {
				continue
			}
			c.dirty = true
			config.Nameservers = nameservers
			c.Network.Wifis[name] = config
		}

		// Check bridges.
		if config, ok := c.Network.Bridges[iface]; ok {
			c.dirty = true
			config.Nameservers = nameservers
			c.Network.Bridges[iface] = config
		}

		// Check bonds.
		if config, ok := c.Network.Bonds[iface]; ok {
			c.dirty = true
			config.Nameservers = nameservers
			c.Network.Bonds[iface] = config
		}

		// Check VLAN interfaces.
		if config, ok := c.Network.VLANs[iface]; ok {
			c.dirty = true
			config.Nameservers = nameservers
			c.Network.VLANs[iface] = config
		}
	}

	// Try to save changes.
	err = np.Save()
	return
}
