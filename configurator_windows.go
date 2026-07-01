package netconfig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type windowsConfigurator struct {
	ifaceBackends []namedIfaceBackend
	panelBackends []namedPanelBackend
	// The tunable settings resolved from the Option values. Its fields
	// (testAddress, pingCount, skipPanels, ...) are promoted and read directly
	// as c.testAddress etc. by the mutating methods.
	*configOptions
}

// Returns the windows network configurator. ctx is accepted to match the Linux
// constructor, whose backend detection queries the init system; nothing here
// needs it. Behaviour is tuned with Option values such as WithTestAddress and
// WithConnectivityCheck; use SetLogger to replace the package-wide logger.
//
// Unlike Linux, no backend is required: winipcfg writes an adapter's addresses
// and routes straight into the registry, so a change persists across a reboot
// without any configuration file behind it. cloud-init is registered when found
// so an image-provisioned host keeps its two sources of truth in step.
func NewConfigurator(ctx context.Context, opts ...Option) (Configurator, error) {
	options := newConfigOptions(opts...)
	c := new(windowsConfigurator)
	c.configOptions = options

	var ci *cloudInit
	ci, err := newCloudInit(options.backupRetention)
	if err != nil {
		logger.Println("error parsing cloud-init:", err)
	}
	if ci != nil {
		c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"cloud-init", ci})
	}
	if _, serr := os.Stat(pleskBin); serr == nil {
		c.panelBackends = append(c.panelBackends, namedPanelBackend{"Plesk", new(plesk)})
	}

	// Detection failures are logged above; they are not fatal to constructing
	// the configurator, so do not propagate them to the caller.
	return c, nil
}

// ipAdapterDHCPState reports whether the adapter runs a DHCP client for each
// address family. Windows exposes the two very differently: DHCPv4 is an
// adapter flag, while there is no DHCPv6 flag at all — an adapter is running a
// DHCPv6 client exactly when one of its addresses says it was learned from one.
func ipAdapterDHCPState(ipAdapter *winipcfg.IPAdapterAddresses) (dhcp4, dhcp6 bool) {
	dhcp4 = ipAdapter.Flags&winipcfg.IPAAFlagDhcpv4Enabled != 0
	for unicast := ipAdapter.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
		ip := unicast.Address.IP()
		if ip == nil || ip.To4() != nil {
			continue
		}
		// IP_ADAPTER_UNICAST_ADDRESS carries the raw Win32 enum, so compare
		// against winipcfg's typed constant for it rather than a bare 3.
		if unicast.PrefixOrigin == int32(winipcfg.PrefixOriginDHCP) {
			dhcp6 = true
			break
		}
	}
	return dhcp4, dhcp6
}

// Get IP addresses from ip adapter.
func ipAdapterAddresses(ipAdapter *winipcfg.IPAdapterAddresses) (addresses []*net.IPNet) {
	// Parse IP addresses on the adapter. To do so,
	// we need to get the unicast addresses and find
	// a matching prefix to get the subnet length.
	unicast := ipAdapter.FirstUnicastAddress
	for unicast != nil {
		addr := unicast.Address.IP()

		// Check prefixes on the adapter to find the prefix for
		// this address.
		prefix := ipAdapter.FirstPrefix
		for prefix != nil {
			// Get the prefix size.
			pAddr := prefix.Address.IP()
			cidrSize := 32
			if pAddr.To4() == nil {
				cidrSize = 128
			}

			// If the length is the same as the size, skip.
			if int(prefix.PrefixLength) == cidrSize {
				prefix = prefix.Next
				continue
			}

			// Convert prefix to ipnet.
			nPrefix := &net.IPNet{
				IP:   pAddr,
				Mask: net.CIDRMask(int(prefix.PrefixLength), cidrSize),
			}

			// If this is the prefix for the address, we found the
			// subnet length.
			if nPrefix.Contains(addr) {
				// Encode address and add.
				ipnet := &net.IPNet{
					IP:   addr,
					Mask: net.CIDRMask(int(prefix.PrefixLength), cidrSize),
				}
				addresses = append(addresses, ipnet)

				// We found the prefix, so stop searching prefixes.
				prefix = nil
				continue
			}

			// Check the next prefix.
			prefix = prefix.Next
		}

		// Check the next IP addr.
		unicast = unicast.Next
	}

	return
}

// adapterIsPhysical reports whether an adapter is backed by hardware. The
// interface type cannot answer that on its own: Windows hands a Hyper-V virtual
// switch, a VPN client's tunnel, and a real NIC the same Ethernet type. The
// interface row's hardware flag does answer it, and the endpoint flag rules out
// the host's own side of a virtual switch, which claims hardware backing it does
// not have. Adapters whose row cannot be read fall back to the interface type.
func adapterIsPhysical(adapter *winipcfg.IPAdapterAddresses) bool {
	row, err := adapter.LUID.Interface()
	if err != nil {
		return isPhysicalIfType(adapter.IfType)
	}
	if row.InterfaceAndOperStatusFlags&winipcfg.IAOSFEndPointInterface != 0 {
		return false
	}
	return row.InterfaceAndOperStatusFlags&winipcfg.IAOSFHardwareInterface != 0
}

// isPhysicalIfType reports whether an interface type is one a physical NIC uses.
func isPhysicalIfType(ifType winipcfg.IfType) bool {
	switch uint32(ifType) {
	case windows.IF_TYPE_ETHERNET_CSMACD, windows.IF_TYPE_IEEE80211:
		return true
	}
	return false
}

// Get list of interfaces and their configs.
func (c *windowsConfigurator) GetInterfaces(ctx context.Context) (interfaces []*Interface, err error) {
	// Reference of zero IP addresses.
	zeroIP4 := make(net.IP, 4)
	zeroIP6 := make(net.IP, 16)

	// Get routes from Windows.
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}

	// Get adaptures from Windows. GAAFlagSkipDNSServer is intentionally omitted
	// so the per-adapter DNS server list is populated and can be reported back.
	ipAdaters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return nil, err
	}

	// Convert adapters to interfaces.
	for _, ipAdapter := range ipAdaters {
		// Skip loopback adapters using the interface type rather than a
		// locale-dependent friendly name.
		if ipAdapter.IfType == winipcfg.IfType(windows.IF_TYPE_SOFTWARE_LOOPBACK) {
			continue
		}

		i := new(Interface)
		i.Name = ipAdapter.FriendlyName()
		i.MAC = ipAdapter.PhysicalAddress()
		i.Link = ipAdapter.LUID
		i.Up = ipAdapter.OperStatus == winipcfg.IfOperStatusUp
		i.Physical = adapterIsPhysical(ipAdapter)
		i.DHCP4, i.DHCP6 = ipAdapterDHCPState(ipAdapter)
		for _, addr := range ipAdapterAddresses(ipAdapter) {
			if !addr.IP.IsLinkLocalUnicast() {
				i.Addresses = append(i.Addresses, addr)
			}
		}

		// Add DNS servers configured on this adapter. The live resolver list
		// is the source of truth on Windows (analogous to addresses/routes).
		for dns := ipAdapter.FirstDNSServerAddress; dns != nil; dns = dns.Next {
			if ip := dns.Address.IP(); ip != nil {
				i.DNS = append(i.DNS, ip)
			}
		}

		// Add routes.
	routeLoop:
		for _, route := range routes {
			// Only routes on this interface.
			if route.InterfaceLUID != ipAdapter.LUID {
				continue
			}

			// Setup new route to translate.
			r := new(Route)

			// Get the prefix, destination IP and gateway.
			prefix := route.DestinationPrefix.Prefix()
			r.Destination = &net.IPNet{
				IP: prefix.Addr().AsSlice(),
			}
			gateway := net.IP(route.NextHop.Addr().AsSlice())
			r.Gateway = gateway

			// If the gateway is the zero IP, ignore.
			if gateway.Equal(zeroIP4) || gateway.Equal(zeroIP6) {
				continue
			}

			// If this is the gatway route, assign gateway.
			if prefix.Bits() == 0 {
				if gateway.To4() != nil {
					i.Gateway4 = gateway
				} else {
					i.Gateway6 = gateway
				}
				continue
			}

			// Apply prefix to destination.
			if r.Destination.IP.To4() != nil {
				r.Destination.Mask = net.CIDRMask(prefix.Bits(), 32)
			} else {
				r.Destination.Mask = net.CIDRMask(prefix.Bits(), 128)
			}

			// Skip route to own networks.
			for _, addr := range i.Addresses {
				if r.Destination.Contains(addr.IP) && bytes.Equal(r.Destination.Mask, addr.Mask) {
					continue routeLoop
				}
			}

			// Add route to list.
			r.Metric = int(route.Metric)
			i.Routes = append(i.Routes, r)
		}

		// Add interface.
		interfaces = append(interfaces, i)
	}
	return
}

// Add an IP address.
func (c *windowsConfigurator) AddAddress(ctx context.Context, iface string, addr *net.IPNet, gateway net.IP) error {
	// Get routes from Windows.
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return err
	}

	// Get adaptures from Windows.
	ipAdaters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return err
	}

	// Find the ip adapter.
	var ipAdapter *winipcfg.IPAdapterAddresses
	for _, adap := range ipAdaters {
		if adap.FriendlyName() == iface {
			ipAdapter = adap
		}
	}

	// If not found, return err.
	if ipAdapter == nil {
		return fmt.Errorf("no adapter found with name: %s", iface)
	}

	// Determine address family so we can confirm we're not removing
	// the last address on the default gateway.
	family := windows.AF_INET
	zeroIP := make(net.IP, 4)
	if addr.IP.To4() == nil {
		family = windows.AF_INET6
		zeroIP = make(net.IP, 16)
	}
	if gateway != nil && !gateway.Equal(zeroIP) {
		if !addr.Contains(gateway) && !gateway.IsLinkLocalUnicast() {
			return fmt.Errorf("provided gateway is not reachable from network")
		}
	}

	// Get existing addresses.
	exists := false
	var origAddr *net.IPNet
	addresses := ipAdapterAddresses(ipAdapter)
	var prefixes []netip.Prefix
	for a, address := range addresses {
		// If the address already exists, update the netmask.
		if address.IP.Equal(addr.IP) {
			origAddr = address
			exists = true
			address = addr
			addresses[a] = addr
		}

		// Add to prefix list.
		ones, _ := address.Mask.Size()
		var ip netip.Addr
		if address.IP.To4() != nil {
			ip = netip.AddrFrom4([4]byte(address.IP.To4()))
		} else {
			ip = netip.AddrFrom16([16]byte(address.IP.To16()))
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
	}

	// Add if not already existing.
	if !exists {
		if pingTest(ctx, addr.IP.String(), c.pingCount, c.pingTimeout) {
			return fmt.Errorf("the ip we are adding is responding to ping")
		}
		addresses = append(addresses, addr)

		// Add to prefix list.
		ones, _ := addr.Mask.Size()
		var ip netip.Addr
		if addr.IP.To4() != nil {
			ip = netip.AddrFrom4([4]byte(addr.IP.To4()))
		} else {
			ip = netip.AddrFrom16([16]byte(addr.IP.To16()))
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
	}

	// Set the IP addresses on the interface.
	err = ipAdapter.LUID.SetIPAddresses(prefixes)
	if err != nil {
		return err
	}

	// Find the default gateway, and update or remove based on config.
	var origGateway netip.Addr
	var gateway4 net.IP
	var gateway6 net.IP
	for _, route := range routes {
		if route.InterfaceLUID != ipAdapter.LUID {
			continue
		}
		prefix := route.DestinationPrefix.Prefix()
		if prefix.Bits() == 0 {
			if route.NextHop.Family == winipcfg.AddressFamily(family) {
				origGateway = route.NextHop.Addr()
				// If gateway is nil, we're keeping original gateway.
				// If the gateway is the zero IP, we should remove the route.
				// If the gateway is regular, try updating the gateway.
				if gateway == nil {
					gateway = net.IP(route.NextHop.Addr().AsSlice())
				} else if gateway.Equal(zeroIP) {
					err = route.Delete()
					if err != nil {
						return err
					}
					continue
				} else {
					var ip netip.Addr
					if gateway.To4() != nil {
						ip = netip.AddrFrom4([4]byte(gateway.To4()))
					} else {
						ip = netip.AddrFrom16([16]byte(gateway.To16()))
					}
					route.NextHop.SetAddr(ip)
					err = route.Set()
					if err != nil {
						return err
					}
				}
			}
			if route.NextHop.Addr().Is4() {
				gateway4 = net.IP(route.NextHop.Addr().AsSlice())
			} else {
				gateway6 = net.IP(route.NextHop.Addr().AsSlice())
			}
			continue
		}
	}

	// Set gateway as nil on zero IP.
	if gateway.Equal(zeroIP) {
		gateway = nil
	}

	// Test internet to confirm we did not break connection.
	if gateway != nil {
		// If the gateway doesn't exist, add it using the adapter's configured
		// metric for the family instead of a hard-coded value.
		addedGateway := false
		if family == windows.AF_INET && gateway4 == nil {
			ip := netip.AddrFrom4([4]byte(gateway.To4()))
			defaultIP := netip.AddrFrom4([4]byte(zeroIP.To4()))
			err = ipAdapter.LUID.AddRoute(netip.PrefixFrom(defaultIP, 0), ip, ipAdapter.Ipv4Metric)
			if err != nil {
				return err
			}
			gateway4 = gateway
			addedGateway = true
		} else if family == windows.AF_INET6 && gateway6 == nil {
			ip := netip.AddrFrom16([16]byte(gateway.To16()))
			defaultIP := netip.AddrFrom16([16]byte(zeroIP.To16()))
			err = ipAdapter.LUID.AddRoute(netip.PrefixFrom(defaultIP, 0), ip, ipAdapter.Ipv6Metric)
			if err != nil {
				return err
			}
			gateway6 = gateway
			addedGateway = true
		}

		// First ping gateway to ensure ARP works.
		if !c.skipConnectivityCheck {
			pingTest(ctx, gateway.String(), c.pingCount, c.pingTimeout)
		}

		// If the connection broke, then we should restore configurations.
		// The check (and rollback) is skipped when connectivity verification
		// is disabled.
		if !c.skipConnectivityCheck && !testInternet(ctx, c.testAddress, c.connectivityTimeout) {
			// Attempt to restore the original IP list. Rebuild the prefix
			// list in place (rather than shadowing the outer prefixes) from
			// the restored addresses, dropping the newly added address.
			prefixes = nil
			for a, address := range addresses {
				if address.IP.Equal(addr.IP) {
					// If the address did not exist before the change, drop it
					// on rollback rather than restoring a stale value.
					if !exists {
						continue
					}
					address = origAddr
					addresses[a] = origAddr
				}

				// Add to prefix list.
				ones, _ := address.Mask.Size()
				var ip netip.Addr
				if address.IP.To4() != nil {
					ip = netip.AddrFrom4([4]byte(address.IP.To4()))
				} else {
					ip = netip.AddrFrom16([16]byte(address.IP.To16()))
				}
				prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
			}

			// Restore original addresses.
			err = ipAdapter.LUID.SetIPAddresses(prefixes)
			if err != nil {
				return err
			}

			// Try and restore the original gateway.
			if origGateway.IsValid() {
				for _, route := range routes {
					if route.InterfaceLUID != ipAdapter.LUID {
						continue
					}
					prefix := route.DestinationPrefix.Prefix()
					if prefix.Bits() == 0 {
						if route.NextHop.Family == winipcfg.AddressFamily(family) {
							route.NextHop.SetAddr(origGateway)
							err = route.Set()
							if err != nil {
								return err
							}
						}
						if route.NextHop.Addr().Is4() {
							gateway4 = net.IP(route.NextHop.Addr().AsSlice())
						} else {
							gateway6 = net.IP(route.NextHop.Addr().AsSlice())
						}
						continue
					}
				}
			} else if addedGateway {
				if family == windows.AF_INET {
					ip := netip.AddrFrom4([4]byte(gateway.To4()))
					defaultIP := netip.AddrFrom4([4]byte(zeroIP.To4()))
					err = ipAdapter.LUID.DeleteRoute(netip.PrefixFrom(defaultIP, 0), ip)
				} else if family == windows.AF_INET6 {
					ip := netip.AddrFrom16([16]byte(gateway.To16()))
					defaultIP := netip.AddrFrom16([16]byte(zeroIP.To16()))
					err = ipAdapter.LUID.DeleteRoute(netip.PrefixFrom(defaultIP, 0), ip)
				}
				if err != nil {
					return err
				}
			}

			return fmt.Errorf("aborted operation due to loss of internet")
		}
	}

	// Update configuration files. Skip control panels when skipPanels is set.
	applyIfaceAddresses(ctx, c.ifaceBackends, iface, addresses, gateway4, gateway6)
	if !c.skipPanels {
		reloadPanels(ctx, c.panelBackends)
	}

	return nil
}

// prefixesFromAddresses converts a list of addresses to the netip.Prefix list
// expected by winipcfg's SetIPAddresses, preserving order.
func prefixesFromAddresses(addresses []*net.IPNet) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, address := range addresses {
		ones, _ := address.Mask.Size()
		var ip netip.Addr
		if address.IP.To4() != nil {
			ip = netip.AddrFrom4([4]byte(address.IP.To4()))
		} else {
			ip = netip.AddrFrom16([16]byte(address.IP.To16()))
		}
		prefixes = append(prefixes, netip.PrefixFrom(ip, ones))
	}
	return prefixes
}

// Promote an existing address to be the primary address of its family. The
// address must already be present on the adapter. winipcfg's SetIPAddresses
// takes an ordered list, so the addresses are re-applied with addr first; the
// persisted backends likewise encode primary as list position. Connectivity is
// verified and rolled back on failure, mirroring AddAddress.
func (c *windowsConfigurator) SetPrimaryAddress(ctx context.Context, iface string, addr *net.IPNet) error {
	// Get routes from Windows.
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return err
	}

	// Get adaptures from Windows.
	ipAdaters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return err
	}

	// Find the ip adapter.
	var ipAdapter *winipcfg.IPAdapterAddresses
	for _, adap := range ipAdaters {
		if adap.FriendlyName() == iface {
			ipAdapter = adap
		}
	}

	// If not found, return err.
	if ipAdapter == nil {
		return fmt.Errorf("no adapter found with name: %s", iface)
	}

	// Determine address family of the address being promoted.
	family := windows.AF_INET
	if addr.IP.To4() == nil {
		family = windows.AF_INET6
	}

	// Get existing addresses and confirm the target is present.
	original := ipAdapterAddresses(ipAdapter)
	exists := false
	for _, address := range original {
		if address.IP.Equal(addr.IP) {
			exists = true
			break
		}
	}
	if !exists {
		return fmt.Errorf("address not found on adapter")
	}

	// Find the default gateway for each family so the config backends keep them.
	var gateway4 net.IP
	var gateway6 net.IP
	for _, route := range routes {
		if route.InterfaceLUID != ipAdapter.LUID {
			continue
		}
		if route.DestinationPrefix.Prefix().Bits() != 0 {
			continue
		}
		if route.NextHop.Addr().Is4() {
			gateway4 = net.IP(route.NextHop.Addr().AsSlice())
		} else {
			gateway6 = net.IP(route.NextHop.Addr().AsSlice())
		}
	}

	// Reorder so the target address is first in its family.
	reordered, _ := reorderPrimaryAddress(original, addr)

	// If already primary within its family, just re-apply the configuration.
	alreadyPrimary := false
	for _, address := range original {
		isV4 := address.IP.To4() != nil
		if (family == windows.AF_INET) == isV4 {
			alreadyPrimary = address.IP.Equal(addr.IP)
			break
		}
	}
	if !alreadyPrimary {
		// Set the reordered IP addresses on the interface.
		if err = ipAdapter.LUID.SetIPAddresses(prefixesFromAddresses(reordered)); err != nil {
			return err
		}

		// Confirm we did not break connectivity, restoring the original order
		// on failure.
		var gw net.IP
		if family == windows.AF_INET {
			gw = gateway4
		} else {
			gw = gateway6
		}
		if !c.skipConnectivityCheck && gw != nil {
			pingTest(ctx, gw.String(), c.pingCount, c.pingTimeout)
			if !testInternet(ctx, c.testAddress, c.connectivityTimeout) {
				if rerr := ipAdapter.LUID.SetIPAddresses(prefixesFromAddresses(original)); rerr != nil {
					return rerr
				}
				return fmt.Errorf("aborted operation due to loss of internet")
			}
		}
	}

	// Update configuration files with the reordered address list. Skip control
	// panels when skipPanels is set.
	applyIfaceAddresses(ctx, c.ifaceBackends, iface, reordered, gateway4, gateway6)
	if !c.skipPanels {
		reloadPanels(ctx, c.panelBackends)
		setMainIPOnPanels(ctx, c.panelBackends, addr.IP)
	}

	return nil
}

// Remove an IP address.
func (c *windowsConfigurator) RemoveAddress(ctx context.Context, iface string, addr *net.IPNet) error {
	// Get routes from Windows.
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return err
	}

	// Get adaptures from Windows.
	ipAdaters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return err
	}

	// Find the ip adapter.
	var ipAdapter *winipcfg.IPAdapterAddresses
	for _, adap := range ipAdaters {
		if adap.FriendlyName() == iface {
			ipAdapter = adap
		}
	}

	// If not found, return err.
	if ipAdapter == nil {
		return fmt.Errorf("no adapter found with name: %s", iface)
	}

	// Determine address family so we can confirm we're not removing
	// the last address on the default gateway.
	family := windows.AF_INET
	if addr.IP.To4() == nil {
		family = windows.AF_INET6
	}

	// Find the default gateway.
	var gw net.IP
	var gateway4 net.IP
	var gateway6 net.IP
	for _, route := range routes {
		if route.InterfaceLUID != ipAdapter.LUID {
			continue
		}
		prefix := route.DestinationPrefix.Prefix()
		if prefix.Bits() == 0 {
			if route.NextHop.Family == winipcfg.AddressFamily(family) {
				gw = net.IP(route.NextHop.Addr().AsSlice())
			}
			if route.NextHop.Addr().Is4() {
				gateway4 = net.IP(route.NextHop.Addr().AsSlice())
			} else {
				gateway6 = net.IP(route.NextHop.Addr().AsSlice())
			}
			continue
		}
	}

	// Get existing addresses, building the list without the address being
	// removed so both the interface and the config backends drop it.
	// Determine the current primary of the same family (the first address of
	// the family in adapter order); removing it is refused unless explicitly
	// allowed, since it changes the system's source address and can leave a
	// control panel without a main IP.
	isV4 := family == windows.AF_INET
	var primaryOfFamily net.IP
	routeToGateway := false
	var addresses []*net.IPNet
	origAddresses := ipAdapterAddresses(ipAdapter)
	for _, address := range origAddresses {
		if primaryOfFamily == nil {
			if (address.IP.To4() != nil) == isV4 {
				primaryOfFamily = address.IP
			}
		}
		// If the address is the one we're removing, skip it.
		if address.IP.Equal(addr.IP) {
			continue
		}

		// If the gateway can be reached via this IP, note that.
		if gw != nil && (address.Contains(gw) || gw.IsLinkLocalUnicast()) {
			routeToGateway = true
		}

		// Keep the address.
		addresses = append(addresses, address)
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

	// Set the IP addresses on the interface.
	err = ipAdapter.LUID.SetIPAddresses(prefixesFromAddresses(addresses))
	if err != nil {
		return err
	}

	// Confirm removing the address did not break connectivity, the same way
	// AddAddress and SetPrimaryAddress do; if it did, restore the original
	// address list and abort before persisting the change or notifying any
	// panel. The check (and its rollback) is skipped when connectivity
	// verification is disabled.
	if !c.skipConnectivityCheck {
		if gw != nil {
			pingTest(ctx, gw.String(), c.pingCount, c.pingTimeout)
		}
		if !testInternet(ctx, c.testAddress, c.connectivityTimeout) {
			if rerr := ipAdapter.LUID.SetIPAddresses(prefixesFromAddresses(origAddresses)); rerr != nil {
				return rerr
			}
			return fmt.Errorf("removing address %s broke internet connectivity; address restored", addr.IP.String())
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
func (c *windowsConfigurator) AddRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP, metric int) error {
	// Reference of zero IP addresses.
	zeroIP4 := make(net.IP, 4)
	zeroIP6 := make(net.IP, 16)

	// Get adaptures from Windows.
	ipAdaters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return err
	}

	// Find the ip adapter.
	var ipAdapter *winipcfg.IPAdapterAddresses
	for _, adap := range ipAdaters {
		if adap.FriendlyName() == iface {
			ipAdapter = adap
		}
	}

	// If not found, return err.
	if ipAdapter == nil {
		return fmt.Errorf("no adapter found with name: %s", iface)
	}

	// Determine the family.
	family := windows.AF_INET
	if dst.IP.To4() == nil {
		family = windows.AF_INET6
	}

	// Verify the addresses on the interface are not in the destination. This
	// only guards against a redundant route to the interface's own connected
	// subnet; a default route (0.0.0.0/0 or ::/0) always "contains" every
	// address and is exempted, otherwise a default route could never be
	// added through this API at all.
	addresses := ipAdapterAddresses(ipAdapter)
	prefix, _ := dst.Mask.Size()
	if prefix != 0 {
		for _, address := range addresses {
			if dst.Contains(address.IP) {
				return fmt.Errorf("cannot add routes that contains an address on the interface")
			}
		}
	}

	// Add static route. A nil gateway means an on-link route with no next
	// hop; converting a nil net.IP via To4()/To16() yields a 0-length slice,
	// which panics when forced into a [4]byte/[16]byte array, so it is
	// represented as the unspecified address instead, matching how a
	// zero-gateway route is already treated elsewhere in this file as "no
	// gateway" when reading routes back.
	var dstIP netip.Addr
	var gatewayIP netip.Addr
	if family == windows.AF_INET {
		dstIP = netip.AddrFrom4([4]byte(dst.IP.To4()))
		if gateway != nil {
			gatewayIP = netip.AddrFrom4([4]byte(gateway.To4()))
		} else {
			gatewayIP = netip.IPv4Unspecified()
		}
	} else {
		dstIP = netip.AddrFrom16([16]byte(dst.IP.To16()))
		if gateway != nil {
			gatewayIP = netip.AddrFrom16([16]byte(gateway.To16()))
		} else {
			gatewayIP = netip.IPv6Unspecified()
		}
	}
	err = ipAdapter.LUID.AddRoute(netip.PrefixFrom(dstIP, prefix), gatewayIP, uint32(metric))
	if err != nil {
		return err
	}

	// Get routes from Windows.
	var staticRoutes []*Route
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
routeLoop:
	for _, route := range routes {
		// Only routes on this interface.
		if route.InterfaceLUID != ipAdapter.LUID {
			continue
		}

		// Setup new route to translate.
		r := new(Route)

		// Get the prefix, destination IP and gateway.
		prefix := route.DestinationPrefix.Prefix()
		r.Destination = &net.IPNet{
			IP: prefix.Addr().AsSlice(),
		}
		gateway := net.IP(route.NextHop.Addr().AsSlice())
		r.Gateway = gateway

		// If the gateway is the zero IP, ignore.
		if gateway.Equal(zeroIP4) || gateway.Equal(zeroIP6) {
			continue
		}

		// If this is the gatway route, assign gateway.
		if prefix.Bits() == 0 {
			continue
		}

		// Apply prefix to destination.
		if r.Destination.IP.To4() != nil {
			r.Destination.Mask = net.CIDRMask(prefix.Bits(), 32)
		} else {
			r.Destination.Mask = net.CIDRMask(prefix.Bits(), 128)
		}

		// Skip route to own networks.
		for _, addr := range addresses {
			if r.Destination.Contains(addr.IP) && bytes.Equal(r.Destination.Mask, addr.Mask) {
				continue routeLoop
			}
		}

		// Add route to list.
		r.Metric = int(route.Metric)
		staticRoutes = append(staticRoutes, r)
	}

	// Update configuration files.
	applyIfaceRoutes(ctx, c.ifaceBackends, iface, staticRoutes)

	return nil
}

// Remove a static route.
func (c *windowsConfigurator) RemoveRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP) error {
	// Reference of zero IP addresses.
	zeroIP4 := make(net.IP, 4)
	zeroIP6 := make(net.IP, 16)

	// Get adaptures from Windows.
	ipAdaters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return err
	}

	// Find the ip adapter.
	var ipAdapter *winipcfg.IPAdapterAddresses
	for _, adap := range ipAdaters {
		if adap.FriendlyName() == iface {
			ipAdapter = adap
		}
	}

	// If not found, return err.
	if ipAdapter == nil {
		return fmt.Errorf("no adapter found with name: %s", iface)
	}

	// Determine the family.
	family := windows.AF_INET
	if dst.IP.To4() == nil {
		family = windows.AF_INET6
	}

	// Verify the addresses on the interface are not in the destination. This
	// only guards against a redundant route to the interface's own connected
	// subnet; a default route (0.0.0.0/0 or ::/0) always "contains" every
	// address and is exempted, otherwise a default route could never be
	// removed through this API at all.
	addresses := ipAdapterAddresses(ipAdapter)
	prefix, _ := dst.Mask.Size()
	if prefix != 0 {
		for _, address := range addresses {
			if dst.Contains(address.IP) {
				return fmt.Errorf("cannot remove routes that contains an address on the interface")
			}
		}
	}

	// Remove route. A nil gateway means an on-link route with no next hop;
	// converting a nil net.IP via To4()/To16() yields a 0-length slice, which
	// panics when forced into a [4]byte/[16]byte array, so it is represented
	// as the unspecified address instead, matching how a zero-gateway route
	// is already treated elsewhere in this file as "no gateway" when reading
	// routes back.
	var dstIP netip.Addr
	var gatewayIP netip.Addr
	if family == windows.AF_INET {
		dstIP = netip.AddrFrom4([4]byte(dst.IP.To4()))
		if gateway != nil {
			gatewayIP = netip.AddrFrom4([4]byte(gateway.To4()))
		} else {
			gatewayIP = netip.IPv4Unspecified()
		}
	} else {
		dstIP = netip.AddrFrom16([16]byte(dst.IP.To16()))
		if gateway != nil {
			gatewayIP = netip.AddrFrom16([16]byte(gateway.To16()))
		} else {
			gatewayIP = netip.IPv6Unspecified()
		}
	}
	err = ipAdapter.LUID.DeleteRoute(netip.PrefixFrom(dstIP, prefix), gatewayIP)
	if err != nil {
		return err
	}

	// Get routes from Windows.
	var staticRoutes []*Route
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return err
	}
routeLoop:
	for _, route := range routes {
		// Only routes on this interface.
		if route.InterfaceLUID != ipAdapter.LUID {
			continue
		}

		// Setup new route to translate.
		r := new(Route)

		// Get the prefix, destination IP and gateway.
		prefix := route.DestinationPrefix.Prefix()
		r.Destination = &net.IPNet{
			IP: prefix.Addr().AsSlice(),
		}
		gateway := net.IP(route.NextHop.Addr().AsSlice())
		r.Gateway = gateway

		// If the gateway is the zero IP, ignore.
		if gateway.Equal(zeroIP4) || gateway.Equal(zeroIP6) {
			continue
		}

		// If this is the gatway route, assign gateway.
		if prefix.Bits() == 0 {
			continue
		}

		// Apply prefix to destination.
		if r.Destination.IP.To4() != nil {
			r.Destination.Mask = net.CIDRMask(prefix.Bits(), 32)
		} else {
			r.Destination.Mask = net.CIDRMask(prefix.Bits(), 128)
		}

		// Skip route to own networks.
		for _, addr := range addresses {
			if r.Destination.Contains(addr.IP) && bytes.Equal(r.Destination.Mask, addr.Mask) {
				continue routeLoop
			}
		}

		// Add route to list.
		r.Metric = int(route.Metric)
		staticRoutes = append(staticRoutes, r)
	}

	// Update configuration files.
	applyIfaceRoutes(ctx, c.ifaceBackends, iface, staticRoutes)

	return nil
}

// Set the DNS servers and search domains for an interface. The change is
// written to the detected configuration backends (cloud-init) so it survives a
// reboot, and also applied to the live adapter via winipcfg so it takes effect
// immediately.
func (c *windowsConfigurator) SetDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) error {
	applyIfaceDNS(ctx, c.ifaceBackends, iface, servers, searchDomains)
	applyLiveDNSWindows(ctx, iface, servers, searchDomains)
	return nil
}

// runNetsh runs netsh and folds its output into any error. netsh reports its
// failures on stdout, not stderr, so without this a failed call surfaces as a
// bare "exit status 1" with the reason discarded.
func runNetsh(ctx context.Context, args ...string) error {
	out, err := runCommand(ctx, "netsh", args...)
	if err == nil {
		return nil
	}
	if reason := strings.TrimSpace(strings.Join(out, " ")); reason != "" {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, reason)
	}
	return fmt.Errorf("netsh %s: %w", strings.Join(args, " "), err)
}

// The netsh argument builders below all use the named-parameter form rather than
// netsh's positional shorthand ("set address name=X static 1.2.3.4 255.255.255.0
// 1.2.3.1"), which is order-sensitive and reads as a puzzle.

// netshEnableDHCP4Args switches an adapter's IPv4 configuration to DHCP. This
// both records the choice and starts the DHCP client, discarding whatever
// static addresses the adapter held.
func netshEnableDHCP4Args(iface string) []string {
	return []string{"interface", "ipv4", "set", "address", "name=" + iface, "source=dhcp"}
}

// netshDNSFromDHCP4Args makes the adapter take its resolvers from the lease.
// Switching the address source to DHCP does not do this: the DNS servers are a
// separate setting and a statically configured resolver survives the switch.
func netshDNSFromDHCP4Args(iface string) []string {
	return []string{"interface", "ipv4", "set", "dnsservers", "name=" + iface, "source=dhcp"}
}

// netshSetStatic4Args replaces the adapter's IPv4 configuration with a single
// static address. There is no netsh verb for "stop being a DHCP client": an
// adapter leaves DHCP by being given a static address, so this is how DHCPv4 is
// turned off.
//
// A nil gateway is written as "none" rather than omitted. Omitting it leaves the
// previous default gateway in place, which on an adapter that has just stopped
// leasing means keeping a gateway the DHCP server handed out.
func netshSetStatic4Args(iface string, addr *net.IPNet, gateway net.IP) []string {
	args := []string{
		"interface", "ipv4", "set", "address",
		"name=" + iface,
		"source=static",
		"address=" + addr.IP.String(),
		"mask=" + net.IP(addr.Mask).String(),
	}
	if gateway != nil {
		return append(args, "gateway="+gateway.String())
	}
	return append(args, "gateway=none")
}

// netshAddStatic4Args adds a secondary static IPv4 address. "set address"
// replaces the adapter's entire IPv4 configuration with the one address it is
// given, so every address after the first has to be re-added with this.
func netshAddStatic4Args(iface string, addr *net.IPNet) []string {
	return []string{
		"interface", "ipv4", "add", "address",
		"name=" + iface,
		"address=" + addr.IP.String(),
		"mask=" + net.IP(addr.Mask).String(),
	}
}

// netshSetDHCP6Args turns the DHCPv6 client on or off.
//
// IPv6 has no "source=dhcp" counterpart, because Windows does not model DHCPv6
// as an address source. A host runs a DHCPv6 client when a router advertisement
// tells it to, via the M (managed address) and O (other stateful config) bits;
// these two interface flags are the local override of those bits. Router
// discovery is enabled alongside them because DHCPv6 conveys no default route —
// only router advertisements do — so an interface leasing an address with
// router discovery off would have no way to reach anything.
//
// Disabling leaves router discovery alone: whatever default route the RA
// provides is not this call's to take away.
func netshSetDHCP6Args(iface string, enable bool) []string {
	args := []string{"interface", "ipv6", "set", "interface", "interface=" + iface}
	if enable {
		return append(args, "routerdiscovery=enabled", "managedaddress=enabled", "otherstateful=enabled")
	}
	return append(args, "managedaddress=disabled", "otherstateful=disabled")
}

// ipconfigRenewArgs asks the DHCP client to acquire a lease now. Switching the
// address source to DHCP starts the client, but a renew makes the lease arrive
// before this call returns rather than at the client's own pace.
func ipconfigRenewArgs(iface string) []string {
	return []string{"/renew", iface}
}

// requireElevation reports an error unless this process holds an elevated token.
// Every write path below reconfigures a live NIC and fails with a bare access
// denied otherwise; under UAC an account in the Administrators group still runs
// with a filtered standard-user token unless it was explicitly elevated. Saying
// so up front beats a netsh error the caller has to decode.
func requireElevation() error {
	if windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return fmt.Errorf("changing an adapter's DHCP configuration requires an elevated process")
}

// Enable or disable the DHCP client for each address family on an interface.
//
// Windows keeps no configuration file of its own, so unlike Linux the adapter is
// both the persisted configuration and the running system, and there is nothing
// to reconcile later: the netsh calls below record the choice and act on it at
// once. A file backend that is also present (cloudbase-init) is written first,
// so a re-provision does not undo what was just set.
//
// The two families are asymmetric. IPv4 has an address source that can be set to
// dhcp or static. IPv6 does not — DHCPv6 is driven by the router advertisement's
// M and O bits, which netshSetDHCP6Args overrides locally. Note that a DHCPv6
// lease carries no default route, so an interface's IPv6 reachability still
// depends on router advertisements either way.
func (c *windowsConfigurator) SetDHCP(ctx context.Context, iface string, dhcp4, dhcp6 bool) error {
	// Check this before touching anything, so a non-elevated caller is told why
	// rather than left with the file backends written and the adapter untouched.
	if err := requireElevation(); err != nil {
		return err
	}

	applyIfaceDHCP(ctx, c.ifaceBackends, iface, dhcp4, dhcp6)

	var errs []error
	if err := setAdapterDHCP4(ctx, iface, dhcp4); err != nil {
		errs = append(errs, err)
	}
	if err := runNetsh(ctx, netshSetDHCP6Args(iface, dhcp6)...); err != nil {
		errs = append(errs, fmt.Errorf("failed to set dhcp6 on %s: %w", iface, err))
	}
	return errors.Join(errs...)
}

// setAdapterDHCP4 switches the adapter's IPv4 address source.
func setAdapterDHCP4(ctx context.Context, iface string, enable bool) error {
	if enable {
		if err := runNetsh(ctx, netshEnableDHCP4Args(iface)...); err != nil {
			return fmt.Errorf("failed to enable dhcp4 on %s: %w", iface, err)
		}

		// The resolvers are a separate setting that survives the address-source
		// switch; a statically configured one would otherwise outlive the static
		// address it was set alongside. Failing to hand DNS back to the lease
		// leaves a working interface, so it is logged rather than returned.
		if err := runNetsh(ctx, netshDNSFromDHCP4Args(iface)...); err != nil {
			logger.Printf("SetDHCP: %s: enabled dhcp4 but failed to take DNS from the lease: %v", iface, err)
		}

		// Setting the source starts the DHCP client; renewing makes the lease
		// arrive before this call returns. A renew that finds no DHCP server
		// fails, which does not undo the configuration that was just written.
		if _, err := runCommand(ctx, "ipconfig", ipconfigRenewArgs(iface)...); err != nil {
			logger.Printf("SetDHCP: %s: enabled dhcp4 but no lease acquired yet: %v", iface, err)
		}
		return nil
	}

	// An adapter leaves DHCP by being given a static address. Re-assert the
	// addresses it currently holds — which are the leased ones — so it keeps the
	// address it is reachable on and simply stops renewing it.
	adapter, err := findAdapter(iface)
	if err != nil {
		return err
	}

	// An adapter that is not leasing has nothing to convert. Running the static
	// assignment on it anyway would tear its IPv4 configuration down and build
	// it back up for no reason.
	if dhcp4, _ := ipAdapterDHCPState(adapter); !dhcp4 {
		return nil
	}

	addrs := ipv4AdapterAddresses(adapter)
	if len(addrs) == 0 {
		return fmt.Errorf("cannot disable dhcp4 on %s: it holds no IPv4 address to keep statically", iface)
	}

	// "set address" replaces the adapter's whole IPv4 configuration with the one
	// address it is given, so the rest are re-added after it.
	if err := runNetsh(ctx, netshSetStatic4Args(iface, addrs[0], ipAdapterGateway4(adapter))...); err != nil {
		return fmt.Errorf("failed to disable dhcp4 on %s: %w", iface, err)
	}
	var errs []error
	for _, addr := range addrs[1:] {
		if err := runNetsh(ctx, netshAddStatic4Args(iface, addr)...); err != nil {
			errs = append(errs, fmt.Errorf("failed to restore secondary address %s on %s: %w", addr, iface, err))
		}
	}
	return errors.Join(errs...)
}

// findAdapter returns the adapter with the given friendly name, which is the
// name netsh and ipconfig also identify it by.
func findAdapter(iface string) (*winipcfg.IPAdapterAddresses, error) {
	ipAdapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		return nil, err
	}
	for _, ipAdapter := range ipAdapters {
		if ipAdapter.FriendlyName() == iface {
			return ipAdapter, nil
		}
	}
	return nil, fmt.Errorf("no adapter found with name: %s", iface)
}

// ipv4AdapterAddresses returns every non-link-local IPv4 address the adapter
// holds, in the order it holds them, which is what converting it from DHCP to
// static must re-assert.
func ipv4AdapterAddresses(adapter *winipcfg.IPAdapterAddresses) (addrs []*net.IPNet) {
	for _, addr := range ipAdapterAddresses(adapter) {
		if addr.IP.To4() == nil || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// ipAdapterGateway4 returns the adapter's first IPv4 default gateway, or nil.
func ipAdapterGateway4(ipAdapter *winipcfg.IPAdapterAddresses) net.IP {
	for gw := ipAdapter.FirstGatewayAddress; gw != nil; gw = gw.Next {
		if ip := gw.Address.IP(); ip != nil && ip.To4() != nil {
			return ip
		}
	}
	return nil
}
