package netconfig

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/Wifx/gonetworkmanager/v3"
	"github.com/vishvananda/netlink"
)

type nmConnection struct {
	ID         string
	Name       string
	UsingData  bool
	Addresses4 []*net.IPNet
	Addresses6 []*net.IPNet
	Gateway4   net.IP
	Gateway6   net.IP
	Routes4    []*Route
	Routes6    []*Route
	DNS        []net.IP
	DNSSearch  []string
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

	// Get the interface name.
	name, ok := settings["connection"]["interface-name"].(string)
	if !ok {
		err = fmt.Errorf("failed to get interface name")
		return
	}
	conn.Name = name

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

// Verify netplan exists, and try parsing its configurations.
func newNetworkManager() (nm *networkManager, err error) {
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

	// Get connections from NM.
	connections, err := nm.config.ListConnections()
	if err != nil {
		return err
	}

	var errs []error

	// Find the connections that has the interfaces.
	for _, c := range connections {
		// Get the settings of the connection.
		var settings gonetworkmanager.ConnectionSettings
		settings, err = c.GetSettings()
		if err != nil {
			return err
		}

		// Get the interface name.
		name, ok := settings["connection"]["interface-name"].(string)
		if !ok {
			continue
		}
		if name != iface {
			continue
		}

		// Get the interface id.
		id, ok := settings["connection"]["id"].(string)
		if !ok {
			err = fmt.Errorf("failed to get interface id")
			return
		}

		// Update address list for IPv4.
		if len(addrs4) == 0 {
			_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv4.method", "disabled", "ipv4.addresses", "", "ipv4.gateway", "")
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to disable ipv4 on %s: %w", id, err))
			}
		} else {
			gateway4S := ""
			if gateway4 != nil {
				gateway4S = gateway4.String()
			}
			_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv4.method", "manual", "ipv4.addresses", strings.Join(addrs4, ","), "ipv4.gateway", gateway4S)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to set ipv4.addresses on %s: %w", id, err))
			}
		}

		// Update address list for IPv6.
		if len(addrs6) == 0 {
			_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv6.method", "link-local", "ipv6.addresses", "", "ipv6.gateway", "")
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to set ipv6 link-local on %s: %w", id, err))
			}
		} else {
			gateway6S := ""
			if gateway6 != nil {
				gateway6S = gateway6.String()
			}
			_, err = runCommand(ctx, "nmcli", "connection", "modify", id, "ipv6.method", "manual", "ipv6.addresses", strings.Join(addrs6, ","), "ipv6.gateway", gateway6S)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to set ipv6.addresses on %s: %w", id, err))
			}
		}
	}

	return errors.Join(errs...)
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

	// Get connections from NM.
	connections, err := nm.config.ListConnections()
	if err != nil {
		return err
	}

	var errs []error

	// Find the connections that has the interfaces.
	for _, c := range connections {
		// Get the settings of the connection.
		var settings gonetworkmanager.ConnectionSettings
		settings, err = c.GetSettings()
		if err != nil {
			return err
		}

		// Get the interface name.
		name, ok := settings["connection"]["interface-name"].(string)
		if !ok {
			continue
		}
		if name != iface {
			continue
		}

		// Get the interface id.
		id, ok := settings["connection"]["id"].(string)
		if !ok {
			err = fmt.Errorf("failed to get interface id")
			return
		}

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

	// Get connections from NM.
	connections, err := nm.config.ListConnections()
	if err != nil {
		return err
	}

	var errs []error

	// Find the connections that has the interfaces.
	for _, c := range connections {
		// Get the settings of the connection.
		var settings gonetworkmanager.ConnectionSettings
		settings, err = c.GetSettings()
		if err != nil {
			return err
		}

		// Get the interface name.
		name, ok := settings["connection"]["interface-name"].(string)
		if !ok {
			continue
		}
		if name != iface {
			continue
		}

		// Get the interface id.
		id, ok := settings["connection"]["id"].(string)
		if !ok {
			err = fmt.Errorf("failed to get interface id")
			return
		}

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
