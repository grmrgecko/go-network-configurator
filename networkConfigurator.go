package netconfig

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	defaultInternetTestAddress = "http://clients3.google.com/generate_204"
	Public                     = "public-internet"
	Public6                    = "public-internet-6"
)

type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Metric      int
}

func (i *Route) String() string {
	return fmt.Sprintf("%s via %s metric %d", i.Destination.String(), i.Gateway.String(), i.Metric)
}

type Interface struct {
	Name      string
	MAC       net.HardwareAddr
	Addresses []*net.IPNet
	Gateway4  net.IP
	Gateway6  net.IP
	Routes    []*Route
	DNS       []net.IP

	// Up reports whether the interface can carry traffic right now, and
	// Physical whether it is backed by a network device rather than created by
	// the kernel or the hypervisor host — a bridge, bond, VLAN, tunnel, or the
	// veth pair of a container is not physical, a virtio or vmxnet NIC is.
	// Both describe the running system and are only set by GetInterfaces; the
	// Interface values the configuration backends read back leave them false.
	Up       bool
	Physical bool

	// DHCP4 and DHCP6 report whether the interface runs a DHCP client for that
	// address family. They describe the persisted configuration, not the
	// running system: the kernel cannot be asked whether an address arrived
	// from a lease, so these are read back from the configuration backends the
	// same way DNS is. An interface can run a DHCP client and still carry
	// static addresses of the same family.
	DHCP4 bool
	DHCP6 bool

	SearchDomains []string
	Link          any
}

func (i *Interface) String() string {
	var routes []string
	for _, route := range i.Routes {
		routes = append(routes, route.String())
	}
	return fmt.Sprintf(
		"Name: %s MAC: %s Addresses: %v Gateway4: %s Gateway6: %s Routes: [%s]",
		i.Name,
		i.MAC.String(),
		i.Addresses,
		i.Gateway4.String(),
		i.Gateway6.String(),
		strings.Join(routes, ", "),
	)
}

type Configurator interface {
	GetInterfaces(ctx context.Context) ([]*Interface, error)
	AddAddress(ctx context.Context, iface string, addr *net.IPNet, gateway net.IP) error
	SetPrimaryAddress(ctx context.Context, iface string, addr *net.IPNet) error
	RemoveAddress(ctx context.Context, iface string, addr *net.IPNet) error
	AddRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP, metric int) error
	RemoveRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP) error
	SetDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) error

	// SetDHCP turns each address family's DHCP client on or off. Both families
	// are stated explicitly, so a caller moving an interface to DHCPv4 while
	// keeping a static IPv6 address passes (true, false).
	//
	// Adding a static address does not imply disabling DHCP: every backend
	// except ifupdown can carry static addresses alongside a lease, and which
	// of the two the operator wants is not something AddAddress can infer.
	// SetDHCP is how that choice is made.
	//
	// Enabling a family also asks the running system to acquire a lease now,
	// rather than at the next reboot. Disabling one only rewrites the
	// configuration: an interface's existing lease is left in place until it
	// expires or the network is reconfigured, so the call cannot strand a
	// caller that is connected over the leased address.
	SetDHCP(ctx context.Context, iface string, dhcp4, dhcp6 bool) error
}

// ifaceBackend persists interface address, route, DNS, and DHCP changes to an
// on-disk network configuration backend such as netplan, cloud-init, networkd,
// NetworkManager, RHEL network-scripts, or ifupdown.
type ifaceBackend interface {
	SetIfaceAddresses(ctx context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) error
	SetIfaceRoutes(ctx context.Context, iface string, routes []*Route) error
	SetIfaceDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) error
	SetIfaceDHCP(ctx context.Context, iface string, dhcp4, dhcp6 bool) error
}

// dhcpRenewer is an optional capability of a file backend: telling the running
// system to pick up a DHCP client that was just enabled in the configuration,
// so the interface acquires a lease without waiting for a reboot. Each backend
// implements it with its own manager's reconfigure command, which is both the
// least disruptive way to do it and the only one that will not fight the
// manager that owns the interface. cloud-init has no such command — it only
// runs at boot — and so does not implement this.
type dhcpRenewer interface {
	renewDHCP(ctx context.Context, iface string) error
}

// panelBackend persists IP changes to a hosting control panel such as
// cPanel, Plesk, or InterWorx.
type panelBackend interface {
	reload(ctx context.Context) error
	setMainIP(ctx context.Context, addr net.IP) error
	removeIP(ctx context.Context, addr net.IP) error
}

// namedIfaceBackend pairs an ifaceBackend with a label used for logging.
type namedIfaceBackend struct {
	name    string
	backend ifaceBackend
}

// namedPanelBackend pairs a panelBackend with a label used for logging.
type namedPanelBackend struct {
	name    string
	backend panelBackend
}

// applyIfaceAddresses pushes the interface's address configuration to every
// registered file backend. Individual failures are logged but do not abort
// the others, since each backend writes an independent configuration file.
func applyIfaceAddresses(ctx context.Context, backends []namedIfaceBackend, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) {
	for _, b := range backends {
		if err := b.backend.SetIfaceAddresses(ctx, iface, addrs, gateway4, gateway6); err != nil {
			logger.Printf("%s error: %v", b.name, err)
		}
	}
}

// applyIfaceRoutes pushes the interface's static routes to every registered
// file backend, logging but not aborting on individual errors.
func applyIfaceRoutes(ctx context.Context, backends []namedIfaceBackend, iface string, routes []*Route) {
	for _, b := range backends {
		if err := b.backend.SetIfaceRoutes(ctx, iface, routes); err != nil {
			logger.Printf("%s error: %v", b.name, err)
		}
	}
}

// ifaceDNSReader is an optional capability of a file backend: reading back the
// interfaces — including their DNS servers and search domains — from the
// backend's persisted configuration. Every on-disk backend implements this via
// its existing GetInterfaces method.
type ifaceDNSReader interface {
	GetInterfaces() ([]*Interface, error)
}

// boolPtr returns a pointer to v, for the optional booleans in the netplan and
// cloud-init schemas where a nil pointer means "key absent" rather than false.
func boolPtr(v bool) *bool {
	return &v
}

// ipIsIn reports whether ip is already present in addrs.
func ipIsIn(addrs []net.IP, ip net.IP) bool {
	for _, a := range addrs {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

// stringInSlice reports whether s is already present in list.
func stringInSlice(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// mergeBackendState reads the DNS servers, search domains, and DHCP client
// state each backend has persisted and merges them into the matching runtime
// Interface (matched by name). The kernel/netlink layer tracks none of these —
// it cannot say which resolver an interface uses, nor whether an address came
// from a lease — so the backends are the source of truth for these fields.
//
// DNS entries are de-duplicated so a host running several backends (e.g.
// netplan and cloud-init) does not list each resolver more than once. The DHCP
// flags are OR'd for the same reason a lease is a property of the interface and
// not of the file describing it: if any backend has the client enabled, the
// interface runs one. Per-backend errors are logged and do not abort the merge.
func mergeBackendState(backends []namedIfaceBackend, ifaces []*Interface) {
	byName := make(map[string]*Interface, len(ifaces))
	for _, i := range ifaces {
		byName[i.Name] = i
	}
	for _, nb := range backends {
		reader, ok := nb.backend.(ifaceDNSReader)
		if !ok {
			continue
		}
		backendIfaces, err := reader.GetInterfaces()
		if err != nil {
			logger.Printf("%s: error reading DNS: %v", nb.name, err)
			continue
		}
		for _, bi := range backendIfaces {
			target := byName[bi.Name]
			if target == nil {
				continue
			}
			target.DHCP4 = target.DHCP4 || bi.DHCP4
			target.DHCP6 = target.DHCP6 || bi.DHCP6
			for _, ip := range bi.DNS {
				if ip == nil || ipIsIn(target.DNS, ip) {
					continue
				}
				target.DNS = append(target.DNS, ip)
			}
			for _, d := range bi.SearchDomains {
				if d == "" || stringInSlice(target.SearchDomains, d) {
					continue
				}
				target.SearchDomains = append(target.SearchDomains, d)
			}
		}
	}
}

// applyIfaceDHCP pushes the interface's DHCP client state to every registered
// file backend. Unlike the other apply helpers this one reports whether any
// backend accepted the change: a caller that is about to ask the running system
// for a lease needs to know that at least one configuration file now asks for
// one, otherwise the lease would be acquired and then lost on the next reboot.
// Individual failures are logged and do not abort the others, since each
// backend writes an independent configuration file — and ifupdown in particular
// rejects requests its one-stanza-per-family model cannot express.
func applyIfaceDHCP(ctx context.Context, backends []namedIfaceBackend, iface string, dhcp4, dhcp6 bool) (applied bool) {
	for _, b := range backends {
		if err := b.backend.SetIfaceDHCP(ctx, iface, dhcp4, dhcp6); err != nil {
			logger.Printf("%s error: %v", b.name, err)
			continue
		}
		applied = true
	}
	return applied
}

// renewDHCPOnBackends asks every backend that can reconfigure the running
// system to do so, so an interface whose DHCP client was just enabled acquires
// a lease now instead of at the next reboot. Backends that cannot — cloud-init,
// which only runs at boot — are skipped. Errors are logged rather than
// returned: the configuration has already been written, and a manager that
// declined to reconfigure has not undone that.
func renewDHCPOnBackends(ctx context.Context, backends []namedIfaceBackend, iface string) {
	for _, b := range backends {
		renewer, ok := b.backend.(dhcpRenewer)
		if !ok {
			continue
		}
		if err := renewer.renewDHCP(ctx, iface); err != nil {
			logger.Printf("%s: error renewing DHCP on %s: %v", b.name, iface, err)
		}
	}
}

// applyIfaceDNS pushes the interface's DNS servers and search domains to every
// registered file backend, logging but not aborting on individual errors.
func applyIfaceDNS(ctx context.Context, backends []namedIfaceBackend, iface string, servers []net.IP, searchDomains []string) {
	for _, b := range backends {
		if err := b.backend.SetIfaceDNS(ctx, iface, servers, searchDomains); err != nil {
			logger.Printf("%s error: %v", b.name, err)
		}
	}
}

// reloadPanels tells every registered control panel to re-read the system's
// IP addresses, logging but not aborting on individual errors.
func reloadPanels(ctx context.Context, backends []namedPanelBackend) {
	for _, b := range backends {
		if err := b.backend.reload(ctx); err != nil {
			logger.Printf("%s error: %v", b.name, err)
		}
	}
}

// setMainIPOnPanels tells every registered control panel to repoint its main
// IP to the given address, logging but not aborting on individual errors.
func setMainIPOnPanels(ctx context.Context, backends []namedPanelBackend, ip net.IP) {
	for _, b := range backends {
		if err := b.backend.setMainIP(ctx, ip); err != nil {
			logger.Printf("%s error: %v", b.name, err)
		}
	}
}

// removeIPFromPanels tells every registered control panel to release an IP
// address, logging but not aborting on individual errors.
func removeIPFromPanels(ctx context.Context, backends []namedPanelBackend, ip net.IP) {
	for _, b := range backends {
		if err := b.backend.removeIP(ctx, ip); err != nil {
			logger.Printf("%s error: %v", b.name, err)
		}
	}
}

// reorderPrimaryAddress returns addrs with target moved to the front, making it
// the first address of its family and therefore the primary in every backend
// (IPADDR0 / IPV6ADDR) and at runtime. The relative order of all other
// addresses is preserved, so the other address family is left untouched.
// Returns false if target is not present in addrs.
func reorderPrimaryAddress(addrs []*net.IPNet, target *net.IPNet) ([]*net.IPNet, bool) {
	found := false
	reordered := make([]*net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP.Equal(target.IP) {
			found = true
			continue
		}
		reordered = append(reordered, addr)
	}
	if !found {
		return addrs, false
	}
	return append([]*net.IPNet{target}, reordered...), true
}

// Interface name ranks, ordered by how likely a NIC of that kind is to be the
// one carrying a host's internet traffic.
const (
	ifaceRankWired = iota
	ifaceRankWireless
	ifaceRankOther
)

// wiredNamePrefixes and wirelessNamePrefixes match the kernel's classic (eth0,
// wlan0) and predictable (eno1, ens3, enp1s0, enx.., em1, wlp2s0) names as well
// as the friendly names Windows reports ("Ethernet 2", "Wi-Fi"). Compared
// against a lower-cased name.
var (
	wiredNamePrefixes    = []string{"eth", "en", "em"}
	wirelessNamePrefixes = []string{"wl", "wifi", "wi-fi"}
)

// FindPhysicalInterfaces returns the host's physical interfaces — leaving out
// the bridges, bonds, VLANs, tunnels, and container veth pairs that should
// never be handed a public address — ordered so the interface most likely to be
// the one a caller wants to configure for internet access comes first.
//
// Interfaces that are up sort ahead of those that are down, then those already
// carrying a default gateway (IPv4 ahead of IPv6-only), then wired ahead of
// wireless, and finally by name read the way a human reads it, so eth0 comes
// before eth1 and eth2 before eth10.
//
// This is a ranking rather than a decision: a caller looking for an interface
// that meets some further requirement — one not already holding a public
// address, say — filters the returned slice and takes the first survivor.
func FindPhysicalInterfaces(ifaces []*Interface) []*Interface {
	physical := make([]*Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Physical {
			physical = append(physical, iface)
		}
	}
	sort.SliceStable(physical, func(i, j int) bool {
		return preferInterface(physical[i], physical[j])
	})
	return physical
}

// preferInterface reports whether a should be offered ahead of b as the
// interface to configure for internet access.
func preferInterface(a, b *Interface) bool {
	if a.Up != b.Up {
		return a.Up
	}
	if ag, bg := gatewayRank(a), gatewayRank(b); ag != bg {
		return ag < bg
	}
	if an, bn := ifaceNameRank(a.Name), ifaceNameRank(b.Name); an != bn {
		return an < bn
	}
	return naturalLess(a.Name, b.Name)
}

// gatewayRank orders an interface by the default gateway it already carries.
// An interface the host currently reaches the internet over is the surest guess
// at the one it should keep reaching the internet over.
func gatewayRank(iface *Interface) int {
	switch {
	case iface.Gateway4 != nil:
		return 0
	case iface.Gateway6 != nil:
		return 1
	}
	return 2
}

// ifaceNameRank guesses an interface's kind from its name. The name is all
// there is to go on: neither netlink nor the Windows IP Helper API reports
// whether a NIC is wired or wireless in a way that survives both platforms.
func ifaceNameRank(name string) int {
	lower := strings.ToLower(name)
	for _, p := range wirelessNamePrefixes {
		if strings.HasPrefix(lower, p) {
			return ifaceRankWireless
		}
	}
	for _, p := range wiredNamePrefixes {
		if strings.HasPrefix(lower, p) {
			return ifaceRankWired
		}
	}
	return ifaceRankOther
}

// Take a name and a list of interfaces and finds an interface by its name.
func FindInterfaceByName(name string, ifaces []*Interface) *Interface {
	switch name {
	case Public:
		// The interface that carries the IPv4 default gateway.
		for _, iface := range ifaces {
			if iface.Gateway4 != nil {
				return iface
			}
		}
	case Public6:
		// The interface that carries the IPv6 default gateway.
		for _, iface := range ifaces {
			if iface.Gateway6 != nil {
				return iface
			}
		}
	default:
		// An interface with the specified name.
		for _, iface := range ifaces {
			if iface.Name == name {
				return iface
			}
		}
	}
	return nil
}
