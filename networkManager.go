package netconfig

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Wifx/gonetworkmanager/v3"
	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"
)

type nmConnection struct {
	ID         string
	Name       string
	UsingData  bool
	Method4    string
	Method6    string
	Addresses4 []*net.IPNet
	Addresses6 []*net.IPNet
	Gateway4   net.IP
	Gateway6   net.IP
	Routes4    []*Route
	Routes6    []*Route
	DNS        []net.IP
	DNSSearch  []string
}

// dhcpState reports whether each family's DHCP client is enabled. IPv4 "auto"
// means DHCPv4. For IPv6, "auto" means router advertisements plus DHCPv6 when
// the router asks for it, and "dhcp" means DHCPv6 alone; both run a client.
func (c *nmConnection) dhcpState() (dhcp4, dhcp6 bool) {
	dhcp4 = c.Method4 == "auto"
	dhcp6 = c.Method6 == "auto" || c.Method6 == "dhcp"
	return dhcp4, dhcp6
}

// nmStaticMethod4 is the ipv4.method to leave behind when DHCPv4 is turned off:
// "manual" when the connection still carries static addresses to serve, and
// "disabled" when turning off the lease leaves it with no IPv4 at all.
func nmStaticMethod4(hasAddrs bool) string {
	if hasAddrs {
		return "manual"
	}
	return "disabled"
}

// nmStaticMethod6 is the ipv6.method counterpart. An IPv6 interface with no
// addresses keeps its link-local one rather than losing IPv6 entirely, which is
// what "disabled" would do.
func nmStaticMethod6(hasAddrs bool) string {
	if hasAddrs {
		return "manual"
	}
	return "link-local"
}

type networkManager struct {
	config gonetworkmanager.Settings
}

// nmNameservers extracts DNS server IPs from a NetworkManager ipv4/ipv6
// settings group. It prefers the modern "dns-data" property (array of strings)
// and falls back to the legacy "dns" property, which encodes IPv4 servers as an
// array of uint32 and IPv6 servers as an array of byte arrays.
func nmNameservers(group map[string]any) []net.IP {
	var servers []net.IP
	if data, ok := group["dns-data"].([]string); ok {
		for _, s := range data {
			if ip := net.ParseIP(s); ip != nil {
				servers = append(servers, ip)
			}
		}
		return servers
	}
	if data, ok := group["dns"].([]uint32); ok {
		for _, u := range data {
			if ip := uint2IP(u); len(ip) > 0 {
				servers = append(servers, ip)
			}
		}
		return servers
	}
	if data, ok := group["dns"].([][]byte); ok {
		for _, b := range data {
			if ip := net.IP(b); ip != nil {
				servers = append(servers, ip)
			}
		}
	}
	return servers
}

// nmSearchDomains extracts the DNS search list from a NetworkManager ipv4/ipv6
// settings group.
func nmSearchDomains(group map[string]any) []string {
	if data, ok := group["dns-search"].([]string); ok {
		return append([]string(nil), data...)
	}
	return nil
}

// Parse a network manager connection settings map to get network configurations.
func (*networkManager) ParseConnection(settings gonetworkmanager.ConnectionSettings) (conn *nmConnection, err error) {
	conn = new(nmConnection)

	// Get the interface id.
	id, ok := settings["connection"]["id"].(string)
	if !ok {
		err = fmt.Errorf("failed to get interface id")
		return
	}
	conn.ID = id

	// Get the interface name. A profile need not name one: NetworkManager binds
	// its own default wired connections to a device by hardware address instead,
	// and those are still connections this configures. Callers that need a name
	// check for an empty one.
	conn.Name, _ = settings["connection"]["interface-name"].(string)

	// Get the addressing method of each family. These decide whether a DHCP
	// client runs, independently of any static addresses parsed below.
	conn.Method4, _ = settings["ipv4"]["method"].(string)
	conn.Method6, _ = settings["ipv6"]["method"].(string)

	// Get the IPv4 address map, and confirm the newer configuration style is used.
	addrMap, ok := settings["ipv4"]["address-data"]
	if ok {
		// Update the information to show the newer configuration is used.
		conn.UsingData = true

		// Parse the IPv4 address data into the address list.
		if addrMap != nil {
			addrSlice := addrMap.([]map[string]any)
			for _, addr := range addrSlice {
				ip := net.ParseIP(addr["address"].(string))
				prefix := addr["prefix"].(uint32)
				conn.Addresses4 = append(conn.Addresses4, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(int(prefix), 32),
				})

			}
		}

		// Parse the IPv4 gateway.
		gateway4S, ok := settings["ipv4"]["gateway"].(string)
		if ok {
			conn.Gateway4 = net.ParseIP(gateway4S)
		}

		// Parse the IPv6 addresses.
		addr6Map, ok := settings["ipv6"]["address-data"]
		if ok && addr6Map != nil {
			addrSlice := addr6Map.([]map[string]any)
			for _, addr := range addrSlice {
				ip := net.ParseIP(addr["address"].(string))
				prefix := addr["prefix"].(uint32)
				conn.Addresses6 = append(conn.Addresses6, &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(int(prefix), 128),
				})

			}
		}

		// Parse the IPv6 gateway.
		gateway6S, ok := settings["ipv6"]["gateway"].(string)
		if ok {
			conn.Gateway6 = net.ParseIP(gateway6S)
		}

		// Parse the IPv4 static route data.
		routeMap, ok := settings["ipv4"]["route-data"]
		if ok && routeMap != nil {
			routeSlice := routeMap.([]map[string]any)
			for _, route := range routeSlice {
				dstIP := net.ParseIP(route["dest"].(string))
				prefix := route["prefix"].(uint32)
				r := new(Route)
				r.Destination = &net.IPNet{
					IP:   dstIP,
					Mask: net.CIDRMask(int(prefix), 32),
				}
				r.Gateway = net.ParseIP(route["next-hop"].(string))
				r.Metric = int(route["metric"].(uint32))
				conn.Routes4 = append(conn.Routes4, r)

			}
		}

		// Parse the IPv6 static route data.
		route6Map, ok := settings["ipv6"]["route-data"]
		if ok && route6Map != nil {
			routeSlice := route6Map.([]map[string]any)
			for _, route := range routeSlice {
				dstIP := net.ParseIP(route["dest"].(string))
				prefix := route["prefix"].(uint32)
				r := new(Route)
				r.Destination = &net.IPNet{
					IP:   dstIP,
					Mask: net.CIDRMask(int(prefix), 128),
				}
				r.Gateway = net.ParseIP(route["next-hop"].(string))
				r.Metric = int(route["metric"].(uint32))
				conn.Routes6 = append(conn.Routes6, r)

			}
		}
	} else {
		// This is the old style configuration, we do not parse
		// these unless the new style is missing.

		// Get the zero IP assignment so we can ignore them for
		// gateway addresses.
		zeroIP := make(net.IP, 4)
		zeroIP6 := make(net.IP, 16)

		// Parse IPv4 address slices.
		addrSlice, ok := settings["ipv4"]["addresses"].([][]uint32)
		if ok {
			for _, addr := range addrSlice {
				gateway := uint2IP(addr[2])
				if gateway != nil && !gateway.Equal(zeroIP) {
					conn.Gateway4 = gateway
				}
				conn.Addresses4 = append(conn.Addresses4, &net.IPNet{
					IP:   uint2IP(addr[0]),
					Mask: net.CIDRMask(int(addr[1]), 32),
				})
			}
		}

		// Parse IPv6 address slices.
		addr6Slice, ok := settings["ipv6"]["addresses"].([][]any)
		if ok {
			for _, addr := range addr6Slice {
				gateway := net.IP(addr[2].([]byte))
				if gateway != nil && !gateway.Equal(zeroIP6) {
					conn.Gateway6 = gateway
				}
				conn.Addresses6 = append(conn.Addresses6, &net.IPNet{
					IP:   net.IP(addr[0].([]byte)),
					Mask: net.CIDRMask(int(addr[1].(uint32)), 128),
				})
			}
		}

		// Parse IPv4 static routes.
		routeSlice, ok := settings["ipv4"]["routes"].([][]uint32)
		if ok {
			for _, route := range routeSlice {
				r := new(Route)
				r.Destination = &net.IPNet{
					IP:   uint2IP(route[0]),
					Mask: net.CIDRMask(int(route[1]), 32),
				}
				r.Gateway = uint2IP(route[2])
				r.Metric = int(route[3])
				conn.Routes4 = append(conn.Routes4, r)
			}
		}

		// Parse IPv6 static routes.
		route6Slice, ok := settings["ipv6"]["routes"].([][]any)
		if ok {
			for _, route := range route6Slice {
				r := new(Route)
				r.Destination = &net.IPNet{
					IP:   net.IP(route[0].([]byte)),
					Mask: net.CIDRMask(int(route[1].(uint32)), 128),
				}
				r.Gateway = net.IP(route[2].([]byte))
				r.Metric = int(route[3].(uint32))
				conn.Routes6 = append(conn.Routes6, r)
			}
		}
	}

	// Parse DNS servers and search domains from both families. DNS is stored
	// independently of the address style, so it is read for both new and old
	// configurations.
	if ipv4, ok := settings["ipv4"]; ok {
		conn.DNS = append(conn.DNS, nmNameservers(ipv4)...)
		conn.DNSSearch = append(conn.DNSSearch, nmSearchDomains(ipv4)...)
	}
	if ipv6, ok := settings["ipv6"]; ok {
		conn.DNS = append(conn.DNS, nmNameservers(ipv6)...)
		conn.DNSSearch = append(conn.DNSSearch, nmSearchDomains(ipv6)...)
	}

	return
}

// nmTarget is a saved connection that configures an interface, paired with the
// id nmcli is driven with.
type nmTarget struct {
	ID       string
	Settings gonetworkmanager.ConnectionSettings
}

// nmSettingsMAC returns the hardware address a profile is pinned to, or an empty
// string when it is pinned to none. D-Bus reports mac-address as a byte array,
// but a profile read back from a keyfile can surface it already printed, so both
// are accepted.
func nmSettingsMAC(settings gonetworkmanager.ConnectionSettings) string {
	for _, group := range []string{"802-3-ethernet", "802-11-wireless"} {
		switch mac := settings[group]["mac-address"].(type) {
		case string:
			return mac
		case []byte:
			if len(mac) != 0 {
				return net.HardwareAddr(mac).String()
			}
		}
	}
	return ""
}

// nmActiveConnectionUUID returns the uuid of the profile NetworkManager has
// active on iface. An interface with nothing active on it, and a host whose
// nmcli cannot answer, both return an empty string: this only ever adds
// candidates to a match, so failing to resolve it costs nothing beyond what
// the interface name alone would have found.
func nmActiveConnectionUUID(ctx context.Context, iface string) string {
	out, err := runCommand(ctx, "nmcli", "-g", "GENERAL.CON-UUID", "device", "show", iface)
	if err != nil {
		return ""
	}
	for _, line := range out {
		line = strings.TrimSpace(line)
		// nmcli prints "--" for a device that is not connected.
		if line != "" && line != "--" {
			return line
		}
	}
	return ""
}

// nmDeviceMAC returns the hardware address of iface as the running system
// reports it, or an empty string when there is no such device.
func nmDeviceMAC(iface string) string {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return ""
	}
	return link.Attrs().HardwareAddr.String()
}

// connectionsFor returns the saved connections that configure iface.
//
// A profile that names an interface is bound to it and is the whole answer when
// one exists. NetworkManager also binds profiles to a device by other means:
// the default wired connection it creates for a device with no profile of its
// own names no interface at all, and a profile can be pinned to a hardware
// address instead. Matching on the name alone left a host whose only profile
// was one of those with nothing to write to -- the change applied to the
// running system and disappeared on the next reboot -- so when nothing names
// the interface, the profile the device is actually running and any profile
// pinned to its hardware address are matched instead.
//
// The fallback is only reached when the name matches nothing, so a host whose
// profiles are named in the ordinary way pays neither of its lookups.
func (nm *networkManager) connectionsFor(ctx context.Context, iface string) ([]nmTarget, error) {
	connections, err := nm.config.ListConnections()
	if err != nil {
		return nil, err
	}

	// Read every profile once; both passes below work from the same snapshot.
	var all []nmTarget
	for _, c := range connections {
		settings, serr := c.GetSettings()
		if serr != nil {
			return nil, serr
		}
		id, ok := settings["connection"]["id"].(string)
		if !ok || id == "" {
			// Without an id there is nothing to point nmcli at.
			continue
		}
		all = append(all, nmTarget{ID: id, Settings: settings})
	}

	// Profiles bound to the interface by name.
	matched := matchByIfaceName(all, iface)
	if len(matched) != 0 {
		return matched, nil
	}

	// Nothing names it: resolve what the device is running and what it is, and
	// match on those instead.
	matched = matchByDevice(all, nmActiveConnectionUUID(ctx, iface), nmDeviceMAC(iface))
	if len(matched) == 0 {
		logger.Printf("NetworkManager has no connection profile for %s; nothing to persist to", iface)
	}
	return matched, nil
}

// matchByIfaceName returns the profiles bound to iface by name.
func matchByIfaceName(all []nmTarget, iface string) []nmTarget {
	var matched []nmTarget
	for _, t := range all {
		if name, _ := t.Settings["connection"]["interface-name"].(string); name == iface {
			matched = append(matched, t)
		}
	}
	return matched
}

// matchByDevice returns the profiles bound to a device by something other than
// its name: the one it is currently running, and any pinned to its hardware
// address. A profile that names an interface is bound there and is never a
// candidate here, whichever interface that is. Either identifier may be empty
// on a host where it could not be resolved, which matches nothing rather than
// everything.
func matchByDevice(all []nmTarget, activeUUID, mac string) []nmTarget {
	var matched []nmTarget
	for _, t := range all {
		if name, _ := t.Settings["connection"]["interface-name"].(string); name != "" {
			continue
		}
		if uuid, _ := t.Settings["connection"]["uuid"].(string); activeUUID != "" && uuid == activeUUID {
			matched = append(matched, t)
			continue
		}
		if pinned := nmSettingsMAC(t.Settings); mac != "" && pinned != "" && strings.EqualFold(pinned, mac) {
			matched = append(matched, t)
		}
	}
	return matched
}

// nmBusName is the well-known D-Bus name the NetworkManager daemon takes once
// it is running. Until some process owns it, there is nothing on the bus to
// answer a configuration call.
const nmBusName = "org.freedesktop.NetworkManager"

// nmBusNameOwned reports whether the NetworkManager daemon currently owns its
// bus name — the "is the socket live" question. It is asked before any property
// is read, because NetworkManager is D-Bus activatable: reading a property on
// an unowned name asks the bus to *start* the daemon. Waiting for a service to
// come up on its own must not be the thing that launches it.
func nmBusNameOwned(conn *dbus.Conn) (bool, error) {
	var owned bool
	err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, nmBusName).Store(&owned)
	return owned, err
}

// nmOnBus reports whether the NetworkManager daemon owns its bus name, opening
// the system bus to ask. It answers the narrower question networkManagerReady
// asks first: whether there is a daemon to configure at all, regardless of how
// far along its startup is.
func nmOnBus() (bool, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return false, err
	}
	return nmBusNameOwned(conn)
}

// networkManagerReady reports whether NetworkManager is on the bus and has
// finished starting up. The two are distinct: the daemon takes its bus name
// early, then spends a while bringing up the connections it is configured to
// activate at boot. Its Startup property stays true for that window, and a
// connection modified during it can be overwritten as startup completes.
//
// A missing system bus is reported as "not ready" rather than as a hard error,
// because a host early enough in boot to beat NetworkManager can also be early
// enough to beat dbus-daemon.
func networkManagerReady() (bool, error) {
	owned, err := nmOnBus()
	if err != nil || !owned {
		return false, err
	}

	daemon, err := gonetworkmanager.NewNetworkManager()
	if err != nil {
		return false, err
	}
	startup, err := daemon.GetPropertyStartup()
	if err != nil {
		return false, err
	}
	return !startup, nil
}

// newNetworkManager waits for the NetworkManager daemon to be ready, then opens
// its settings interface. Unlike the file backends, NetworkManager is
// configured through a running daemon, so a configurator built while it is
// still starting would hold a settings handle that reports no connections and
// accepts no changes.
//
// Running out of that wait is not by itself a reason to give up on the backend.
// The Startup property stays true for as long as any device is still working
// through its initial activation, and a device retrying a lease no DHCP server
// will ever answer holds it true indefinitely -- a state a host is most likely
// to be in precisely when someone is about to give it a static address. What
// the wait buys is a daemon that will not rewrite the change as it finishes
// starting; a daemon that is on the bus is still configurable without it, and
// dropping the backend instead would report a NetworkManager host as having
// nowhere to persist its network configuration at all.
func newNetworkManager(ctx context.Context, readyTimeout time.Duration) (nm *networkManager, err error) {
	if waitErr := waitForServiceReady(ctx, "NetworkManager", readyTimeout, networkManagerReady); waitErr != nil {
		// A cancelled caller is not waiting for an answer any more.
		if ctx.Err() != nil {
			return nil, waitErr
		}
		owned, busErr := nmOnBus()
		if busErr != nil || !owned {
			return nil, waitErr
		}
		logger.Printf("NetworkManager has not finished starting up; configuring it anyway: %v", waitErr)
	}

	config, err := gonetworkmanager.NewSettings()
	if err != nil {
		return
	}
	nm = &networkManager{
		config: config,
	}
	return
}

// Get interfaces configured.
func (nm *networkManager) GetInterfaces() (interfaces []*Interface, err error) {
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

	// Get connections from NM.
	connections, err := nm.config.ListConnections()

	// Add devices to the list.
	for _, c := range connections {
		// Get the settings of the connection.
		var settings gonetworkmanager.ConnectionSettings
		settings, err = c.GetSettings()
		if err != nil {
			return
		}

		// Parse the connection. A connection that fails to parse (for example
		// a VPN or bridge-slave profile with no interface-name) is skipped,
		// not fatal, so this must not touch the named err return: doing so
		// would let the last connection processed decide whether the whole
		// call reports an error, discarding an otherwise fully-populated
		// interfaces slice depending purely on D-Bus connection ordering.
		connection, parseErr := nm.ParseConnection(settings)
		if parseErr != nil {
			continue
		}

		// A profile that names no interface cannot be reported as one: there is
		// no device name to key the merge by. It is still written to, which
		// connectionsFor resolves separately.
		if connection.Name == "" {
			continue
		}

		// Find the MAC address and link.
		var mac net.HardwareAddr
		var foundLink netlink.Link
		for _, link := range links {
			if link.Attrs().Name == connection.Name {
				mac = link.Attrs().HardwareAddr
				foundLink = link
			}
		}

		// Setup new interface.
		i := new(Interface)
		i.Name = connection.Name
		i.MAC = mac
		i.Link = foundLink
		i.DHCP4, i.DHCP6 = connection.dhcpState()

		// Append addresses.
		for _, addr := range connection.Addresses4 {
			i.Addresses = append(i.Addresses, addr)
		}
		for _, addr := range connection.Addresses6 {
			i.Addresses = append(i.Addresses, addr)
		}

		// Add gateways.
		if connection.Gateway4 != nil {
			i.Gateway4 = connection.Gateway4
		}
		if connection.Gateway6 != nil {
			i.Gateway6 = connection.Gateway6
		}

		// Append routes.
		for _, route := range connection.Routes4 {
			i.Routes = append(i.Routes, route)
		}
		for _, route := range connection.Routes6 {
			i.Routes = append(i.Routes, route)
		}

		// Add DNS servers and search domains.
		i.DNS = append(i.DNS, connection.DNS...)
		i.SearchDomains = append(i.SearchDomains, connection.DNSSearch...)

		// Add the interface.
		interfaces = append(interfaces, i)
	}

	return
}

// Set the IP addresses on an interface.
func (nm *networkManager) SetIfaceAddresses(ctx context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) (err error) {
	// Separate addresses by addr4 and addr6.
	var addrs4 []string
	var addrs6 []string
	for _, addr := range addrs {
		if addr.IP.To4() == nil {
			addrs6 = append(addrs6, addr.String())
		} else {
			addrs4 = append(addrs4, addr.String())
		}
	}

	// Find the connections that configure the interface.
	targets, err := nm.connectionsFor(ctx, iface)
	if err != nil {
		return err
	}

	var errs []error

	for _, t := range targets {
		id, settings := t.ID, t.Settings

		// Read the current addressing method of each family. NetworkManager
		// serves static addresses alongside a lease when the method is "auto",
		// so a connection already on DHCP keeps it: changing an address is not
		// a request to stop using DHCP, and SetIfaceDHCP is how that is asked
		// for. Only a family that is not already leasing is moved to "manual"
		// (or off, when it is left with no addresses at all).
		method4, _ := settings["ipv4"]["method"].(string)
		method6, _ := settings["ipv6"]["method"].(string)
		conn := &nmConnection{Method4: method4, Method6: method6}
		dhcp4, dhcp6 := conn.dhcpState()

		// Update address list for IPv4.
		newMethod4 := nmStaticMethod4(len(addrs4) != 0)
		if dhcp4 {
			newMethod4 = "auto"
		}
		gateway4S := ""
		if gateway4 != nil && len(addrs4) != 0 {
			gateway4S = gateway4.String()
		}
		_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv4.method", newMethod4, "ipv4.addresses", strings.Join(addrs4, ","), "ipv4.gateway", gateway4S)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv4.addresses on %s: %w", id, err))
		}

		// Update address list for IPv6.
		newMethod6 := nmStaticMethod6(len(addrs6) != 0)
		if dhcp6 {
			newMethod6 = method6
		}
		gateway6S := ""
		if gateway6 != nil && len(addrs6) != 0 {
			gateway6S = gateway6.String()
		}
		_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv6.method", newMethod6, "ipv6.addresses", strings.Join(addrs6, ","), "ipv6.gateway", gateway6S)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv6.addresses on %s: %w", id, err))
		}
	}

	return errors.Join(errs...)
}

// Set the DHCP client state on an interface.
func (nm *networkManager) SetIfaceDHCP(ctx context.Context, iface string, dhcp4, dhcp6 bool) (err error) {
	// Find the connections that configure the interface.
	targets, err := nm.connectionsFor(ctx, iface)
	if err != nil {
		return err
	}

	var errs []error

	for _, t := range targets {
		id, settings := t.ID, t.Settings

		// Parse the connection so turning a lease off can fall back to the
		// method that still serves whatever static addresses it holds.
		conn, parseErr := nm.ParseConnection(settings)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("failed to parse connection %s: %w", id, parseErr))
			continue
		}

		// Switch the IPv4 method. "auto" is DHCPv4; NetworkManager keeps
		// serving any ipv4.addresses the connection carries alongside it.
		method4 := "auto"
		if !dhcp4 {
			method4 = nmStaticMethod4(len(conn.Addresses4) != 0)
		}
		if _, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv4.method", method4); err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv4.method on %s: %w", id, err))
		}

		// Switch the IPv6 method. A connection already on "auto" is left there
		// rather than forced to "dhcp": both run a DHCPv6 client, and "auto"
		// additionally honors router advertisements, which turning it into
		// "dhcp" would silently switch off.
		method6 := "auto"
		if dhcp6 && conn.Method6 == "dhcp" {
			method6 = "dhcp"
		} else if !dhcp6 {
			method6 = nmStaticMethod6(len(conn.Addresses6) != 0)
		}
		if _, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv6.method", method6); err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv6.method on %s: %w", id, err))
		}
	}

	return errors.Join(errs...)
}

// renewDHCP has NetworkManager reapply the connection profile to the device, so
// a client it was just told to run starts and acquires a lease. `device
// reapply` changes the device in place and, unlike `connection up`, does not
// tear the link down first.
func (nm *networkManager) renewDHCP(ctx context.Context, iface string) error {
	_, err := runCommand(ctx, "nmcli", "device", "reapply", iface)
	return err
}

// Set static routes to interface.
func (nm *networkManager) SetIfaceRoutes(ctx context.Context, iface string, routes []*Route) (err error) {
	// Build route slices.
	var routes4 []string
	var routes6 []string
	for _, route := range routes {
		r := fmt.Sprintf("%s %s %d", route.Destination.String(), route.Gateway, route.Metric)
		if route.Destination.IP.To4() == nil {
			routes6 = append(routes6, r)
		} else {
			routes4 = append(routes4, r)
		}
	}

	// Find the connections that configure the interface.
	targets, err := nm.connectionsFor(ctx, iface)
	if err != nil {
		return err
	}

	var errs []error

	for _, t := range targets {
		id := t.ID

		// Update routes.
		_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv4.routes", strings.Join(routes4, ","))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv4.routes on %s: %w", id, err))
		}
		_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv6.routes", strings.Join(routes6, ","))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv6.routes on %s: %w", id, err))
		}
	}

	return errors.Join(errs...)
}

// Set DNS servers and search domains on interface.
func (nm *networkManager) SetIfaceDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) (err error) {
	// Separate DNS servers by family; NetworkManager keeps them under the
	// ipv4 and ipv6 settings.
	var dns4 []string
	var dns6 []string
	for _, ip := range servers {
		if ip == nil {
			continue
		}
		if ip.To4() == nil {
			dns6 = append(dns6, ip.String())
		} else {
			dns4 = append(dns4, ip.String())
		}
	}
	search := strings.Join(searchDomains, ",")

	// Find the connections that configure the interface.
	targets, err := nm.connectionsFor(ctx, iface)
	if err != nil {
		return err
	}

	var errs []error

	for _, t := range targets {
		id := t.ID

		// Update DNS servers and search domains for each family. Also disable
		// automatic DNS from DHCP/RA so the static servers are the only
		// resolvers used.
		_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv4.dns", strings.Join(dns4, ","), "ipv4.dns-search", search, "ipv4.ignore-auto-dns", "yes")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv4.dns on %s: %w", id, err))
		}
		_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv6.dns", strings.Join(dns6, ","), "ipv6.dns-search", search, "ipv6.ignore-auto-dns", "yes")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to set ipv6.dns on %s: %w", id, err))
		}
	}

	return errors.Join(errs...)
}
