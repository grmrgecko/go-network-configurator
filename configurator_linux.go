package netconfig

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"

	dbus "github.com/coreos/go-systemd/dbus"
	"github.com/vishvananda/netlink"
)

type linuxConfigurator struct {
	ifaceBackends []namedIfaceBackend
	panelBackends []namedPanelBackend
	// The tunable settings resolved from the Option values. Its fields
	// (testAddress, pingCount, skipPanels, ...) are promoted and read directly
	// as c.testAddress etc. by the mutating methods.
	*configOptions
}

// Returns the linux network configurator. Behaviour is tuned with Option
// values such as WithTestAddress and WithConnectivityCheck; use SetLogger to
// replace the package-wide logger.
func NewConfigurator(opts ...Option) (configurator Configurator, err error) {
	options := newConfigOptions(opts...)
	// Connect to dbus for systemd and list active units to determine which
	// network managers are running. This fails on systems without a usable
	// systemd D-Bus interface, so we fall back to detecting legacy managers:
	//   - Ubuntu 14.04: Upstart is PID 1 and org.freedesktop.systemd1 is served
	//     by systemd-shim, which lacks ListUnits ("No such method 'ListUnits'").
	//   - CentOS 5/6: no systemd1 on the bus at all, so ListUnits (or the
	//     connection itself) fails with ServiceUnknown.
	activeUnits := make(map[string]bool)
	conn, derr := dbus.NewWithContext(context.Background())
	if derr == nil {
		defer conn.Close()
		var units []dbus.UnitStatus
		units, derr = conn.ListUnitsContext(context.Background())
		for _, unit := range units {
			if unit.ActiveState == "active" {
				activeUnits[unit.Name] = true
			}
		}
	}
	if derr != nil {
		logger.Printf("unable to list systemd units, falling back to legacy detection: %v", derr)
		activeUnits = legacyActiveUnits()
	}

	// Determine candidates based on unit status.
	c := new(linuxConfigurator)
	c.configOptions = options
	configurator = c

	// Detect each backend. A nil concrete pointer wrapped in an interface is
	// itself non-nil, so backends are collected as concrete pointers here and
	// only registered below when non-nil.
	var (
		nd  *networkd
		nm  *networkManager
		ns  *networkScripts
		iud *ifUpDown
		np  *netplan
		ci  *cloudInit
	)
	if activeUnits["systemd-networkd.service"] {
		nd, err = newNetworkd(options.backupRetention)
		if err != nil {
			logger.Println("error parsing networkd config:", err)
		}
	}
	if activeUnits["NetworkManager.service"] {
		nm, err = newNetworkManager()
		if err != nil {
			logger.Println("error parsing network manager config:", err)
		}
	}
	if activeUnits["network.service"] {
		ns, err = newNetworkScripts(options.backupRetention)
		if err != nil {
			logger.Println("error parsing network scripts:", err)
		}
	}

	// If the ifupdown config exists, add its config.
	if _, serr := os.Stat(ifUpDownConfig); serr == nil {
		iud, err = newIfUpDown(options.backupRetention)
		if err != nil {
			logger.Println("error prasing ifupdown:", err)
		}
	}

	_, err = exec.LookPath("netplan")
	if err == nil {
		np, err = newNetplan(options.backupRetention)
		if err != nil {
			logger.Println("error parsing netplan:", err)
		}
	}
	ci, err = newCloudInit(options.backupRetention)
	if err != nil {
		logger.Println("error parsing cloud-init:", err)
	}

	// Register the detected file backends in a stable apply order. Each backend
	// received the configured backup retention from its constructor above.
	if np != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"Netplan", np})
	}
	if ci != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"cloud-init", ci})
	}
	if nm != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"NetworkManager", nm})
	}
	if nd != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"Networkd", nd})
	}
	if ns != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"NetworkScripts", ns})
	}
	if iud != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"IfUpDown", iud})
	}

	// Register the detected control panels in a stable apply order.
	if _, serr := os.Stat(cpanelBin); serr == nil {
		c.panelBackends = append(c.panelBackends, namedPanelBackend{"cPanel", new(cpanel)})
	}
	if _, serr := os.Stat(pleskBin); serr == nil {
		c.panelBackends = append(c.panelBackends, namedPanelBackend{"Plesk", new(plesk)})
	}
	if _, serr := os.Stat(nodeworxBin); serr == nil {
		c.panelBackends = append(c.panelBackends, namedPanelBackend{"Interworx", new(interworx)})
	}

	// Detection failures are logged above; they are not fatal to constructing
	// the configurator, so do not propagate them to the caller.
	err = nil
	return
}

// legacyActiveUnits detects active network managers on systems that lack a
// usable systemd D-Bus interface, where ListUnits is unavailable: Upstart on
// Ubuntu 14.04 and SysVinit/Upstart on CentOS 5/6. Detection is by config and
// runtime presence rather than by querying any specific init system, so it is
// init-agnostic and spawns no subprocesses.
//
// systemd-networkd cannot run on these systems, and ifupdown is detected
// separately by config-file presence, so only the RHEL network-scripts service
// and NetworkManager are considered here. The returned keys match the systemd
// unit names used by the caller.
func legacyActiveUnits() map[string]bool {
	active := make(map[string]bool)

	// RHEL-family network-scripts has no daemon; presence of its config
	// directory is the best available signal that it manages the network.
	if fi, serr := os.Stat(networkScriptsPath); serr == nil && fi.IsDir() {
		active["network.service"] = true
	}

	// NetworkManager manages the network via its own D-Bus interface; a
	// runtime pid file indicates the daemon is running.
	for _, pidFile := range []string{
		"/var/run/NetworkManager/NetworkManager.pid",
		"/run/NetworkManager/NetworkManager.pid",
	} {
		if _, serr := os.Stat(pidFile); serr == nil {
			active["NetworkManager.service"] = true
			break
		}
	}

	return active
}

// Get list of interfaces and their configs.
func (c *linuxConfigurator) GetInterfaces(ctx context.Context) (interfaces []*Interface, err error) {
	// Connect to netlink.
	var h *netlink.Handle
	h, err = netlink.NewHandle()
	if err != nil {
		return
	}
	defer h.Close()

	// Get list of interfaces.
	var links []netlink.Link
	links, err = h.LinkList()
	if err != nil {
		return
	}

	// Add interfaces to list.
	for _, link := range links {
		// Skip the localhost interface.
		if link.Attrs().Name == "lo" {
			continue
		}

		// Make interface.
		i := new(Interface)
		i.Name = link.Attrs().Name
		i.MAC = link.Attrs().HardwareAddr
		i.Link = link

		// Add IP Addresses.
		addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if addr.IP.IsLinkLocalUnicast() {
				continue
			}
			i.Addresses = append(i.Addresses, addr.IPNet)
		}

		// Add static routes.
		routes, err := h.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
	routeLoop:
		for _, route := range routes {
			// Skip nil routes.
			if route.Gw == nil {
				continue
			}

			// The gateway route is 0.0.0.0/0 or ::/0.
			ones, _ := route.Dst.Mask.Size()
			if ones == 0 {
				if route.Gw.To4() == nil {
					i.Gateway6 = route.Gw
				} else {
					i.Gateway4 = route.Gw
				}
				continue
			}

			// Skip route to own networks.
			for _, addr := range addrs {
				if route.Dst.Contains(addr.IP) && bytes.Equal(route.Dst.Mask, addr.Mask) {
					continue routeLoop
				}
			}

			// Make route.
			r := new(Route)
			r.Destination = route.Dst
			r.Gateway = route.Gw
			r.Metric = route.Priority
			i.Routes = append(i.Routes, r)
		}

		// Add interface.
		interfaces = append(interfaces, i)
	}

	// DNS servers and search domains are not exposed via netlink, so merge
	// them in from the persisted backend configurations. This lets callers
	// read back what SetDNS wrote via Interface.DNS and Interface.SearchDomains.
	mergeDNSFromBackends(c.ifaceBackends, interfaces)
	return
}

// Add an IP address.
func (c *linuxConfigurator) AddAddress(ctx context.Context, iface string, addr *net.IPNet, gateway net.IP) error {
	// Connect to netlink.
	h, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer h.Close()

	// Get link by iface name.
	link, err := h.LinkByName(iface)
	if err != nil {
		return err
	}

	// Determine address family so we can confirm we're not removing
	// the last address on the default gateway.
	family := netlink.FAMILY_V4
	zeroIP := net.IPv4zero
	if addr.IP.To4() == nil {
		family = netlink.FAMILY_V6
		zeroIP = net.IPv6zero
	}
	if gateway != nil && !gateway.Equal(zeroIP) {
		if !addr.Contains(gateway) && !gateway.IsLinkLocalUnicast() {
			return fmt.Errorf("provided gateway is not reachable from network")
		}
	}

	// Get existing addresses and save the full pre-change state so we can
	// restore it if the connectivity test fails.
	exists := false
	var addresses []*net.IPNet
	var origAddresses []*net.IPNet
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, address := range addrs {
		// Save a copy of every non-link-local address before any mutation.
		// This must be a distinct *net.IPNet, not address.IPNet itself: when
		// the address already exists below we mutate address.IPNet.Mask in
		// place, and since AddrList's Addr embeds a *net.IPNet, appending the
		// pointer directly here would let that later mutation silently
		// corrupt the pre-change snapshot rollback relies on.
		if !address.IP.IsLinkLocalUnicast() {
			origAddresses = append(origAddresses, &net.IPNet{IP: address.IPNet.IP, Mask: address.IPNet.Mask})
		}

		// If the address already exists, update the netmask.
		if address.IPNet.IP.Equal(addr.IP) {
			exists = true
			address.IPNet.Mask = addr.Mask
			err = h.AddrReplace(link, &address)
			if err != nil {
				return err
			}
		}

		// Ignore link local addresses.
		if address.IP.IsLinkLocalUnicast() {
			continue
		}

		// Add address to list.
		addresses = append(addresses, address.IPNet)
	}

	// Add if not already existing.
	if !exists {
		if pingTest(ctx, addr.IP.String(), c.pingCount, c.pingTimeout) {
			return fmt.Errorf("the ip we are adding is responding to ping")
		}
		err = h.AddrAdd(link, &netlink.Addr{IPNet: addr})
		if err != nil {
			return err
		}
		addresses = append(addresses, addr)
	}

	// Find the default gateway, and update or remove based on config.
	var origRoute netlink.Route
	var gateway4 net.IP
	var gateway6 net.IP
	routes, err := h.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	// A dual-stack host has a default route for each family, and RouteList
	// with FAMILY_ALL always returns the IPv4 routes before the IPv6 ones.
	// Scan until the first default route of each family is captured rather
	// than breaking on the first default route found, otherwise the family
	// we're configuring may never be processed.
	seen4, seen6 := false, false
	for _, route := range routes {
		// The gateway route is 0.0.0.0/0 or ::/0, handled once per family.
		ones, _ := route.Dst.Mask.Size()
		if ones != 0 {
			continue
		}
		if (route.Family == netlink.FAMILY_V4 && seen4) ||
			(route.Family == netlink.FAMILY_V6 && seen6) {
			continue
		}

		if route.Family == family {
			origRoute = route
			// If gateway is nil, we're keeping original gateway.
			// If the gateway is the zero IP, we should remove the route.
			// If the gateway is regular, try updating the gateway.
			if gateway == nil {
				gateway = route.Gw
			} else if gateway.Equal(zeroIP) {
				err = h.RouteDel(&route)
				if err != nil {
					return err
				}
				route.Gw = nil
			} else {
				route.Gw = gateway
				err = h.RouteChange(&route)
				if err != nil {
					return err
				}
			}
		}
		// Capture the (possibly mutated) gateway for the config backends.
		if route.Family == netlink.FAMILY_V4 {
			gateway4 = route.Gw
			seen4 = true
		} else if route.Family == netlink.FAMILY_V6 {
			gateway6 = route.Gw
			seen6 = true
		}
		if seen4 && seen6 {
			break
		}
	}

	// Set gateway as nil on zero IP.
	if gateway.Equal(zeroIP) {
		gateway = nil
	}

	// Test internet to confirm we did not break connection.
	if gateway != nil {
		// If the gateway doesn't exist, add it.
		var addedGateway *netlink.Route
		if family == netlink.FAMILY_V4 && gateway4 == nil {
			addedGateway = &netlink.Route{
				Family:    family,
				LinkIndex: link.Attrs().Index,
				Dst: &net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.CIDRMask(0, 32),
				},
				Gw: gateway,
			}
			err = h.RouteAdd(addedGateway)
			if err != nil {
				return fmt.Errorf("failed to add gateway4 %s: %v", gateway.String(), err)
			}
			gateway4 = gateway
		} else if family == netlink.FAMILY_V6 && gateway6 == nil {
			addedGateway = &netlink.Route{
				Family:    family,
				LinkIndex: link.Attrs().Index,
				Dst: &net.IPNet{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(0, 128),
				},
				Gw: gateway,
			}
			err = h.RouteAdd(addedGateway)
			if err != nil {
				return fmt.Errorf("failed to add gateway6 %s: %v", gateway.String(), err)
			}
			gateway6 = gateway
		}

		// First ping gateway to ensure ARP works, then confirm we did not
		// break connectivity. The check (and its rollback) is skipped when
		// connectivity verification is disabled.
		if !c.skipConnectivityCheck {
			pingTest(ctx, gateway.String(), c.pingCount, c.pingTimeout)

			// If the connection broke, restore the full pre-change address
			// list and default route.
			if !testInternet(ctx, c.testAddress, c.connectivityTimeout) {
				// Remove the address we added so we can rebuild the original
				// address list without it.
				if !exists {
					if derr := h.AddrDel(link, &netlink.Addr{IPNet: addr}); derr != nil {
						return derr
					}
				}

				// Re-apply every original non-link-local address.
				for _, orig := range origAddresses {
					if err = h.AddrReplace(link, &netlink.Addr{IPNet: orig}); err != nil {
						return err
					}
				}

				// Restore the original default route for this family.
				if origRoute.Gw != nil {
					err = h.RouteReplace(&origRoute)
					if err != nil {
						return err
					}
				} else if addedGateway != nil {
					err = h.RouteDel(addedGateway)
					if err != nil {
						return err
					}
				}
				return fmt.Errorf("aborted operation due to loss of internet")
			}
		}
	}

	// Update configuration files. Skip control panels when skipPanels is set.
	applyIfaceAddresses(ctx, c.ifaceBackends, iface, addresses, gateway4, gateway6)
	if !c.skipPanels {
		reloadPanels(ctx, c.panelBackends)
	}

	return nil
}

// Promote an existing address to be the primary address of its family. The
// address must already be present on the interface. At runtime the kernel
// treats the first address inserted in a subnet as primary, so the family's
// addresses are removed and re-added with addr first; the persisted backends
// likewise encode primary as list position. Connectivity is verified and rolled
// back on failure, mirroring AddAddress.
func (c *linuxConfigurator) SetPrimaryAddress(ctx context.Context, iface string, addr *net.IPNet) error {
	// Connect to netlink.
	h, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer h.Close()

	// Get link by iface name.
	link, err := h.LinkByName(iface)
	if err != nil {
		return err
	}

	// Determine address family of the address being promoted.
	family := netlink.FAMILY_V4
	if addr.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	// Get existing addresses. Build the full non-link-local address list (for
	// the config backends) and the ordered same-family sublist (for the runtime
	// reorder), and confirm the target address is actually present.
	exists := false
	var addresses []*net.IPNet
	var familyAddrs []netlink.Addr
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, address := range addrs {
		if address.IPNet.IP.Equal(addr.IP) {
			exists = true
		}

		// Ignore link local addresses.
		if address.IP.IsLinkLocalUnicast() {
			continue
		}

		addresses = append(addresses, address.IPNet)

		// Collect this family's addresses in kernel order for the reorder.
		isV4 := address.IP.To4() != nil
		if (family == netlink.FAMILY_V4) == isV4 {
			familyAddrs = append(familyAddrs, address)
		}
	}

	// The address must already exist on the interface.
	if !exists {
		return fmt.Errorf("address not found on interface")
	}

	// Find the default gateway for this family so the config backends keep the
	// gateway and so we can restore the route if reordering drops it.
	var gateway4 net.IP
	var gateway6 net.IP
	var familyRoute netlink.Route
	haveFamilyRoute := false
	routes, err := h.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	// As in AddAddress, a dual-stack host has a default route per family and
	// RouteList returns IPv4 before IPv6, so capture the first default of each
	// family rather than breaking on the first one found.
	seen4, seen6 := false, false
	for _, route := range routes {
		ones, _ := route.Dst.Mask.Size()
		if ones != 0 {
			continue
		}
		if route.Family == netlink.FAMILY_V4 && !seen4 {
			gateway4 = route.Gw
			seen4 = true
		} else if route.Family == netlink.FAMILY_V6 && !seen6 {
			gateway6 = route.Gw
			seen6 = true
		} else {
			continue
		}
		if route.Family == family {
			familyRoute = route
			haveFamilyRoute = true
		}
		if seen4 && seen6 {
			break
		}
	}

	// If the address is already primary, there is nothing to reorder at runtime;
	// fall through to re-apply the configuration so it matches the running state.
	if len(familyAddrs) != 0 && familyAddrs[0].IPNet.IP.Equal(addr.IP) {
		addresses, _ = reorderPrimaryAddress(addresses, addr)
		applyIfaceAddresses(ctx, c.ifaceBackends, iface, addresses, gateway4, gateway6)
		if !c.skipPanels {
			reloadPanels(ctx, c.panelBackends)
			setMainIPOnPanels(ctx, c.panelBackends, addr.IP)
		}
		return nil
	}

	// Build the desired runtime order with the target address first.
	desired := append([]netlink.Addr{}, familyAddrs...)
	for i, a := range desired {
		if a.IPNet.IP.Equal(addr.IP) {
			desired = append(desired[:i], desired[i+1:]...)
			break
		}
	}
	target := netlink.Addr{}
	for _, a := range familyAddrs {
		if a.IPNet.IP.Equal(addr.IP) {
			target = a
			break
		}
	}
	desired = append([]netlink.Addr{target}, desired...)

	// reapply removes the family's addresses and re-adds them in order, then
	// restores the family's default route if it was dropped along with its
	// connected address.
	reapply := func(order []netlink.Addr) error {
		for i := range familyAddrs {
			if derr := h.AddrDel(link, &familyAddrs[i]); derr != nil {
				return derr
			}
		}
		for i := range order {
			a := order[i]
			if aerr := h.AddrReplace(link, &a); aerr != nil {
				return aerr
			}
		}
		if !haveFamilyRoute {
			return nil
		}
		// Re-add the default route if reordering removed it.
		present := false
		cur, rerr := h.RouteList(link, family)
		if rerr != nil {
			return rerr
		}
		for _, route := range cur {
			ones, _ := route.Dst.Mask.Size()
			if ones == 0 && route.Gw.Equal(familyRoute.Gw) {
				present = true
				break
			}
		}
		if !present {
			r := familyRoute
			if rerr := h.RouteReplace(&r); rerr != nil {
				return rerr
			}
		}
		return nil
	}

	// Apply the new order.
	if err = reapply(desired); err != nil {
		return err
	}

	// Confirm we did not break connectivity, restoring the original order on
	// failure. Skipped when connectivity verification is disabled.
	if !c.skipConnectivityCheck && haveFamilyRoute && familyRoute.Gw != nil {
		pingTest(ctx, familyRoute.Gw.String(), c.pingCount, c.pingTimeout)
		if !testInternet(ctx, c.testAddress, c.connectivityTimeout) {
			if rerr := reapply(familyAddrs); rerr != nil {
				return rerr
			}
			return fmt.Errorf("aborted operation due to loss of internet")
		}
	}

	// Update configuration files with the reordered address list. Skip control
	// panels when skipPanels is set.
	addresses, _ = reorderPrimaryAddress(addresses, addr)
	applyIfaceAddresses(ctx, c.ifaceBackends, iface, addresses, gateway4, gateway6)
	if !c.skipPanels {
		reloadPanels(ctx, c.panelBackends)
		setMainIPOnPanels(ctx, c.panelBackends, addr.IP)
	}

	return nil
}

// Remove an IP address.
func (c *linuxConfigurator) RemoveAddress(ctx context.Context, iface string, addr *net.IPNet) error {
	// Connect to netlink.
	h, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer h.Close()

	// Get link by iface name.
	link, err := h.LinkByName(iface)
	if err != nil {
		return err
	}

	// Determine address family so we can confirm we're not removing
	// the last address on the default gateway.
	family := netlink.FAMILY_V4
	if addr.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	// Find the default gateway.
	var gw net.IP
	var gateway4 net.IP
	var gateway6 net.IP
	routes, err := h.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	// As in AddAddress, a dual-stack host has a default route per family and
	// RouteList returns IPv4 before IPv6, so capture the first default of
	// each family rather than breaking on the first one found.
	seen4, seen6 := false, false
	for _, route := range routes {
		// The gateway route is 0.0.0.0/0 or ::/0, handled once per family.
		ones, _ := route.Dst.Mask.Size()
		if ones != 0 {
			continue
		}
		if route.Family == netlink.FAMILY_V4 && !seen4 {
			gateway4 = route.Gw
			seen4 = true
		} else if route.Family == netlink.FAMILY_V6 && !seen6 {
			gateway6 = route.Gw
			seen6 = true
		} else {
			continue
		}
		if route.Family == family {
			gw = route.Gw
		}
		if seen4 && seen6 {
			break
		}
	}

	// Get existing addresses.
	var nlAddr *netlink.Addr
	routeToGateway := false
	var addresses []*net.IPNet
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	// Determine the current primary address of the same family: the first
	// non-link-local address of the family in kernel order. Removing the
	// primary changes the system's source address and can leave a control
	// panel without a main IP, so it is refused unless explicitly allowed.
	isV4 := family == netlink.FAMILY_V4
	var primaryOfFamily net.IP
	for _, address := range addrs {
		if address.IP.IsLinkLocalUnicast() {
			continue
		}
		if (address.IP.To4() != nil) != isV4 {
			continue
		}
		primaryOfFamily = address.IP
		break
	}
	for _, address := range addrs {
		// If the address already exists, set the nlAddr and skip.
		if address.IPNet.IP.Equal(addr.IP) {
			nlAddr = &address
			continue
		}

		// If the gateway can be reached via this IP, note that.
		if gw != nil && (address.IPNet.Contains(gw) || gw.IsLinkLocalUnicast()) {
			routeToGateway = true
		}

		// Ignore link local addresses.
		if address.IP.IsLinkLocalUnicast() {
			continue
		}

		// Add the address.
		addresses = append(addresses, address.IPNet)
	}

	// Refuse to remove the primary address unless explicitly allowed. The
	// caller is expected to promote another address first; WithAllowPrimaryRemoval
	// overrides this for deliberate teardowns.
	if primaryOfFamily != nil && primaryOfFamily.Equal(addr.IP) && !c.allowPrimaryRemoval {
		return fmt.Errorf("refusing to remove primary address %s; promote another address first or enable WithAllowPrimaryRemoval", addr.IP.String())
	}

	// If we cannot reach the gateway after removing the address,
	// we should error out.
	if gw != nil && !routeToGateway {
		return fmt.Errorf("unable to reach gateway after removing address.")
	}

	// We should be able to remove the address if it exists.
	if nlAddr != nil {
		err = h.AddrDel(link, nlAddr)
		if err != nil {
			return err
		}

		// Confirm removing the address did not break connectivity, the same
		// way AddAddress and SetPrimaryAddress do; if it did, restore the
		// address and abort before persisting the change or notifying any
		// panel. The check (and its rollback) is skipped when connectivity
		// verification is disabled.
		if !c.skipConnectivityCheck {
			if gw != nil {
				pingTest(ctx, gw.String(), c.pingCount, c.pingTimeout)
			}
			if !testInternet(ctx, c.testAddress, c.connectivityTimeout) {
				if rerr := h.AddrReplace(link, nlAddr); rerr != nil {
					return rerr
				}
				return fmt.Errorf("removing address %s broke internet connectivity; address restored", addr.IP.String())
			}
		}
	}

	// Update configuration files. When skipPanels is set, control panels are
	// left untouched and only the network-manager files are rewritten.
	if !c.skipPanels {
		removeIPFromPanels(ctx, c.panelBackends, addr.IP)
	}
	applyIfaceAddresses(ctx, c.ifaceBackends, iface, addresses, gateway4, gateway6)

	return nil
}

// Add a static route.
func (c *linuxConfigurator) AddRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP, metric int) error {
	// Connect to netlink.
	h, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer h.Close()

	// Get link by iface name.
	link, err := h.LinkByName(iface)
	if err != nil {
		return err
	}

	// Determine the family.
	family := netlink.FAMILY_V4
	if dst.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}

	// Verify the addresses on the interface are not in the destination. This
	// only guards against a redundant route to the interface's own connected
	// subnet; a default route (0.0.0.0/0 or ::/0) always "contains" every
	// address and is exempted, otherwise a default route could never be
	// added through this API at all.
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	if ones, _ := dst.Mask.Size(); ones != 0 {
		for _, address := range addrs {
			if dst.Contains(address.IP) {
				return fmt.Errorf("cannot add routes that contains an address on the interface")
			}
		}
	}

	// Add static route.
	staticRoute := &netlink.Route{
		Family:    family,
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gateway,
		Priority:  metric,
	}
	err = h.RouteAdd(staticRoute)
	if err != nil {
		return err
	}

	// Get all static routes.
	var staticRoutes []*Route
	routes, err := h.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
routeLoop:
	for _, route := range routes {
		// The gateway route is 0.0.0.0/0 or ::/0.
		ones, _ := route.Dst.Mask.Size()
		if ones == 0 {
			continue
		}

		// Skip route to own networks.
		for _, addr := range addrs {
			if route.Dst.Contains(addr.IP) && bytes.Equal(route.Dst.Mask, addr.Mask) {
				continue routeLoop
			}
		}

		// Make route.
		r := new(Route)
		r.Destination = route.Dst
		r.Gateway = route.Gw
		r.Metric = route.Priority
		staticRoutes = append(staticRoutes, r)
	}

	// Update configuration files.
	applyIfaceRoutes(ctx, c.ifaceBackends, iface, staticRoutes)

	return nil
}

// Remove a static route.
func (c *linuxConfigurator) RemoveRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP) error {
	// Connect to netlink.
	h, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer h.Close()

	// Get link by iface name.
	link, err := h.LinkByName(iface)
	if err != nil {
		return err
	}

	// Verify the addresses on the interface are not in the destination. This
	// only guards against a redundant route to the interface's own connected
	// subnet; a default route (0.0.0.0/0 or ::/0) always "contains" every
	// address and is exempted, otherwise a default route could never be
	// removed through this API at all.
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	if ones, _ := dst.Mask.Size(); ones != 0 {
		for _, address := range addrs {
			if dst.Contains(address.IP) {
				return fmt.Errorf("cannot remove routes that contains an address on the interface")
			}
		}
	}

	// Get all static routes.
	var staticRoutes []*Route
	routes, err := h.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
routeLoop:
	for _, route := range routes {
		// The gateway route is 0.0.0.0/0 or ::/0.
		ones, _ := route.Dst.Mask.Size()
		if ones == 0 {
			continue
		}

		// Skip route to own networks.
		for _, addr := range addrs {
			if route.Dst.Contains(addr.IP) && bytes.Equal(route.Dst.Mask, addr.Mask) {
				continue routeLoop
			}
		}

		// If this is the route we're removing, remove it.
		if route.Dst.Contains(dst.IP) && bytes.Equal(route.Dst.Mask, dst.Mask) &&
			route.Gw.Equal(gateway) {
			err = h.RouteDel(&route)
			if err != nil {
				return err
			}
			continue
		}

		// Make route.
		r := new(Route)
		r.Destination = route.Dst
		r.Gateway = route.Gw
		r.Metric = route.Priority
		staticRoutes = append(staticRoutes, r)
	}

	// Update configuration files.
	applyIfaceRoutes(ctx, c.ifaceBackends, iface, staticRoutes)

	return nil
}

// Set the DNS servers and search domains for an interface. The change is
// written to every detected configuration backend so it survives a reboot, and
// also applied to the live resolver (systemd-resolved via resolvectl, or
// /etc/resolv.conf where resolvectl is unavailable) so it takes effect
// immediately rather than only on the next reload.
func (c *linuxConfigurator) SetDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) error {
	applyIfaceDNS(ctx, c.ifaceBackends, iface, servers, searchDomains)
	applyLiveDNS(ctx, iface, servers, searchDomains)
	return nil
}
