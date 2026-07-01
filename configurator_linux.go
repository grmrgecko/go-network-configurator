package netconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

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

// Returns the linux network configurator. Backends are auto-detected; ctx
// bounds that detection, which queries systemd over D-Bus and may shell out to
// chkconfig and netplan. Behaviour is tuned with Option values such as
// WithTestAddress and WithConnectivityCheck; use SetLogger to replace the
// package-wide logger.
func NewConfigurator(ctx context.Context, opts ...Option) (Configurator, error) {
	options := newConfigOptions(opts...)

	// Snapshot what the init system knows about its units once. Every backend
	// check below is answered from it, falling back to the SysV mechanisms for
	// any service systemd cannot speak for.
	initSys := newInitState(ctx)

	c := new(linuxConfigurator)
	c.configOptions = options

	// Detect each backend. A nil concrete pointer wrapped in an interface is
	// itself non-nil, so backends are collected as concrete pointers here and
	// only registered below when non-nil. Each constructor's error is kept local:
	// a backend that fails to parse is skipped, not fatal, and must not leak into
	// the error returned to the caller.
	var (
		nd  *networkd
		nm  *networkManager
		ns  *networkScripts
		iud *ifUpDown
		np  *netplan
	)
	if initSys.detected(ctx, "systemd-networkd") {
		var err error
		if nd, err = newNetworkd(options.backupRetention); err != nil {
			logger.Println("error parsing networkd config:", err)
		}
	}

	// NetworkManager's pid file is checked as well as its unit, so the daemon is
	// still found on a host whose systemd could not be queried. Detection here
	// includes a unit that is enabled but not yet started, so newNetworkManager
	// waits for the daemon to reach the bus and finish starting: this program
	// may be run early enough in boot to beat it, and NetworkManager is
	// configured through that daemon rather than through a file.
	if initSys.detected(ctx, "NetworkManager") || networkManagerRunning() {
		var err error
		if nm, err = newNetworkManager(ctx, options.serviceReadyTimeout); err != nil {
			logger.Println("error parsing network manager config:", err)
		}
	}

	// The RHEL-family network-scripts service. newNetworkScripts returns an error
	// when /etc/sysconfig/network-scripts is absent, so a host that has the
	// service registered but no scripts directory registers no backend.
	if initSys.detected(ctx, "network") {
		var err error
		if ns, err = newNetworkScripts(options.backupRetention); err != nil {
			logger.Println("error parsing network scripts:", err)
		}
	}

	if ifUpDownDetected(ctx, initSys) {
		var err error
		if iud, err = newIfUpDown(options.backupRetention); err != nil {
			logger.Println("error parsing ifupdown:", err)
		}
	}

	// netplan is gated on its binary resolving before newNetplan runs `netplan
	// info`, so a host without netplan pays no subprocess and logs no failure.
	if commandExists("netplan") {
		var err error
		if np, err = newNetplan(ctx, options.backupRetention); err != nil {
			logger.Println("error parsing netplan:", err)
		}
	}

	// cloud-init has no service to detect: it runs once at boot and is found by
	// its configuration alone, which newCloudInit reports on.
	ci, err := newCloudInit(options.backupRetention)
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

	// A host with no file backend can still have its running state changed through
	// netlink, but nothing would persist and the change would vanish on the next
	// boot. Fail here rather than hand back a configurator that silently writes
	// nowhere; WithAllowNoBackends opts into it for read-only callers.
	if len(c.ifaceBackends) == 0 {
		// A cancelled context aborts every probe above, which looks identical to
		// a host that genuinely has no backend. Report the real cause.
		if cerr := ctx.Err(); cerr != nil {
			return nil, fmt.Errorf("backend detection did not complete: %w", cerr)
		}
		if !options.allowNoBackends {
			return nil, fmt.Errorf("no network configuration backend detected: address changes would apply to the running system but not survive a reboot (use WithAllowNoBackends to proceed anyway)")
		}
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

	// Detection failures are logged above; a backend that could not be parsed is
	// skipped rather than propagated, so the configurator is returned without an
	// error as long as at least one backend was registered.
	return c, nil
}

// ifUpDownDetected reports whether ifupdown manages this host's network.
// /etc/network/interfaces existing is not enough on its own: it is left behind
// on Ubuntu hosts migrated to netplan and on Debian hosts that have handed the
// network to NetworkManager, so the networking service must also be running or
// enabled. On a host with no discoverable init system there is nothing to
// corroborate against, and the config file's presence is taken as sufficient
// rather than dropping a backend that may well be the only one.
func ifUpDownDetected(ctx context.Context, s *initState) bool {
	if _, err := os.Stat(ifUpDownConfig); err != nil {
		return false
	}
	return s.detected(ctx, "networking") || !initSystemDiscoverable()
}

// linkIsUp reports whether a link can carry traffic. The operational state is
// the honest answer where the driver reports one: an interface that is
// administratively up but has no carrier — an unplugged cable — cannot. Many
// virtual and paravirtual drivers never report an operational state at all, so
// for those the administrative flag stands in.
func linkIsUp(attrs *netlink.LinkAttrs) bool {
	if attrs.OperState == netlink.OperUnknown {
		return attrs.Flags&net.FlagUp != 0
	}
	return attrs.OperState == netlink.OperUp
}

// ensureLinkUp brings an administratively down link up, reporting whether it
// had to. The kernel installs an address's connected route only while its link
// is up, so a gateway added to a down interface is rejected as unreachable and
// the interface has to be raised before its addresses and routes are written.
// Only the administrative flag is consulted, not the operational state that
// linkIsUp prefers: a link that is up and waiting on carrier is already as up
// as this can make it, and setting it up again would say nothing.
func ensureLinkUp(h *netlink.Handle, link netlink.Link) (bool, error) {
	if link.Attrs().Flags&net.FlagUp != 0 {
		return false, nil
	}
	if err := h.LinkSetUp(link); err != nil {
		return false, fmt.Errorf("failed to bring up interface %s: %w", link.Attrs().Name, err)
	}
	return true, nil
}

// linkIsPhysical reports whether a link is backed by a network device rather
// than created by the kernel. rtnetlink names the kind of every software
// device — bridge, bond, veth, vlan, tun, wireguard, dummy — and names no kind
// at all for a driver-backed NIC, which is the "device" this compares against.
// Paravirtual NICs (virtio, vmxnet, xen) are driver-backed and so count as
// physical: a VM's only real NIC is still the one to configure.
func linkIsPhysical(link netlink.Link) bool {
	return link.Type() == "device"
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
		i.Up = linkIsUp(link.Attrs())
		i.Physical = linkIsPhysical(link)

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

	// DNS servers, search domains, and DHCP client state are not exposed via
	// netlink, so merge them in from the persisted backend configurations. This
	// lets callers read back what SetDNS and SetDHCP wrote via Interface.DNS,
	// Interface.SearchDomains, Interface.DHCP4, and Interface.DHCP6.
	mergeBackendState(c.ifaceBackends, interfaces)
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

	// Raise the interface before writing to it. A down link carries no connected
	// route for the address about to be added, so the gateway below would be
	// rejected as unreachable. A link raised here is part of the pre-change state
	// this restores, so put it back down on any path that does not complete.
	broughtUp, err := ensureLinkUp(h, link)
	if err != nil {
		return err
	}
	applied := false
	if broughtUp {
		defer func() {
			if applied {
				return
			}
			if derr := h.LinkSetDown(link); derr != nil {
				logger.Printf("failed to return interface %s to down: %v", iface, derr)
			}
		}()
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
					// Deleting the address above takes with it every route that
					// resolved its nexthop through the address's connected
					// subnet, which is exactly how the gateway added here was
					// reachable. The kernel then has nothing left to delete and
					// answers ESRCH, so treat an already-gone route as removed
					// rather than reporting it over the rollback's own error.
					err = h.RouteDel(addedGateway)
					if err != nil && !errors.Is(err, syscall.ESRCH) {
						return err
					}
				}
				return fmt.Errorf("aborted operation due to loss of internet")
			}
		}
	}

	// The runtime state now holds, so a link raised above stays up.
	applied = true

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

// Enable or disable the DHCP client for each address family on an interface.
func (c *linuxConfigurator) SetDHCP(ctx context.Context, iface string, dhcp4, dhcp6 bool) error {
	if !applyIfaceDHCP(ctx, c.ifaceBackends, iface, dhcp4, dhcp6) {
		return fmt.Errorf("no backend accepted a DHCP change for %s", iface)
	}

	// Enabling a client asks the running system to acquire a lease now. Turning
	// one off does not reconfigure the interface: the existing lease is left to
	// expire, so a caller connected over the leased address is not cut off by a
	// call that was only meant to change what happens on the next boot.
	if dhcp4 || dhcp6 {
		renewDHCPOnBackends(ctx, c.ifaceBackends, iface)
	}
	return nil
}
