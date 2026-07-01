package netconfig

import (
	"context"
	"fmt"
	"net"
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
	Name          string
	MAC           net.HardwareAddr
	Addresses     []*net.IPNet
	Gateway4      net.IP
	Gateway6      net.IP
	Routes        []*Route
	DNS           []net.IP
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
}

// ifaceBackend persists interface address, route, and DNS changes to an on-disk
// network configuration backend such as netplan, cloud-init, networkd,
// NetworkManager, RHEL network-scripts, or ifupdown.
type ifaceBackend interface {
	SetIfaceAddresses(ctx context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) error
	SetIfaceRoutes(ctx context.Context, iface string, routes []*Route) error
	SetIfaceDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) error
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

// mergeDNSFromBackends reads the DNS servers and search domains each backend
// has persisted and merges them into the matching runtime Interface (matched by
// name). The kernel/netlink layer does not track per-interface DNS, so the
// backends are the source of truth for these fields. Entries are de-duplicated
// so a host running several backends (e.g. netplan and cloud-init) does not
// list each resolver more than once. Per-backend errors are logged and do not
// abort the merge.
func mergeDNSFromBackends(backends []namedIfaceBackend, ifaces []*Interface) {
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
