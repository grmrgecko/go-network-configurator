package netconfig

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wifx/gonetworkmanager/v3"
	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNMConnection struct {
	settings gonetworkmanager.ConnectionSettings
}

func (c *mockNMConnection) GetPath() dbus.ObjectPath {
	return ""
}

func (c *mockNMConnection) Update(settings gonetworkmanager.ConnectionSettings) error {
	return nil
}

func (c *mockNMConnection) UpdateUnsaved(settings gonetworkmanager.ConnectionSettings) error {
	return nil
}

func (c *mockNMConnection) Delete() error {
	return nil
}

func (c *mockNMConnection) GetSettings() (gonetworkmanager.ConnectionSettings, error) {
	return c.settings, nil
}

func (c *mockNMConnection) GetSecrets(settingName string) (gonetworkmanager.ConnectionSettings, error) {
	return nil, nil
}

func (c *mockNMConnection) ClearSecrets() error {
	return nil
}

func (c *mockNMConnection) Save() error {
	return nil
}

func (c *mockNMConnection) GetPropertyUnsaved() (bool, error) {
	return false, nil
}

func (c *mockNMConnection) GetPropertyFlags() (uint32, error) {
	return 0, nil
}

func (c *mockNMConnection) GetPropertyFilename() (string, error) {
	return "", nil
}

func (c *mockNMConnection) MarshalJSON() ([]byte, error) {
	s, _ := c.GetSettings()
	return json.Marshal(s)
}

type mockNMSettings struct {
}

func (s *mockNMSettings) ListConnections() ([]gonetworkmanager.Connection, error) {
	var connections []gonetworkmanager.Connection

	connection := &mockNMConnection{
		settings: gonetworkmanager.ConnectionSettings{
			"ipv4": {
				"address-data": []map[string]interface{}(nil),
				"dns-search":   []string{},
				"method":       "auto",
				"route-data":   []map[string]interface{}(nil),
				"routes":       [][]uint32{},
				"addresses":    [][]uint32{},
				"gateway":      "1.2.3.1",
				"route-metric": 100,
				"dhcp-timeout": 45,
			},
			"ipv6": {
				"addr-gen-mode": 3,
				"address-data":  []map[string]interface{}(nil),
				"routes":        [][]interface{}{},
				"dns-search":    []string{},
				"method":        "auto",
				"route-data":    []map[string]interface{}(nil),
				"dhcp-timeout":  45,
				"route-metric":  100,
				"addresses":     [][]interface{}{},
			},
			"proxy": {},
			"connection": {
				"uuid":                 "843f71c2-161d-46e1-9533-195bfdc8ae56",
				"autoconnect-priority": 1,
				"autoconnect-retries":  0,
				"id":                   "test_eth0",
				"interface-name":       "test_eth0",
				"permissions":          []string{},
				"timestamp":            1669049774,
				"type":                 "802-3-ethernet",
			},
			"802-3-ethernet": {
				"auto-negotiate":        false,
				"mac-address-blacklist": []string{},
				"s390-options":          map[string]string{},
			},
		},
	}
	connections = append(connections, connection)

	connection = &mockNMConnection{
		settings: gonetworkmanager.ConnectionSettings{
			"ipv4": {
				"address-data": []map[string]interface{}{
					{
						"address": "1.2.3.4",
						"prefix":  uint32(24),
					},
				},
				"dns-search": []string{},
				"method":     "manual",
				"route-data": []map[string]interface{}{
					{
						"dest":     "10.0.0.0",
						"prefix":   uint32(24),
						"next-hop": "1.2.3.5",
						"metric":   uint32(100),
					},
				},
				"routes":       [][]uint32{},
				"addresses":    [][]uint32{},
				"gateway":      "1.2.3.1",
				"route-metric": 100,
				"dhcp-timeout": 45,
			},
			"ipv6": {
				"addr-gen-mode": 3,
				"address-data":  []map[string]interface{}(nil),
				"routes":        [][]interface{}{},
				"dns-search":    []string{},
				"method":        "auto",
				"route-data":    []map[string]interface{}(nil),
				"dhcp-timeout":  45,
				"route-metric":  100,
				"addresses":     [][]interface{}{},
			},
			"proxy": {},
			"connection": {
				"uuid":                 "843f71c2-161d-46e1-9533-195bfdc8ae56",
				"autoconnect-priority": 1,
				"autoconnect-retries":  0,
				"id":                   "main",
				"interface-name":       "test_eth0.1556",
				"permissions":          []string{},
				"timestamp":            1669049774,
				"type":                 "802-3-ethernet",
			},
			"802-3-ethernet": {
				"auto-negotiate":        false,
				"mac-address-blacklist": []string{},
				"s390-options":          map[string]string{},
			},
		},
	}
	connections = append(connections, connection)

	connection = &mockNMConnection{
		settings: gonetworkmanager.ConnectionSettings{
			"ipv4": {
				"address-data": []map[string]interface{}(nil),
				"dns-search":   []string{},
				"method":       "auto",
				"route-data":   []map[string]interface{}(nil),
				"routes":       [][]uint32{},
				"addresses":    [][]uint32{},
				"route-metric": 100,
				"dhcp-timeout": 45,
			},
			"ipv6": {
				"addr-gen-mode": 3,
				"address-data": []map[string]interface{}{
					{
						"address": "fc00:aa8:7160:d9eb:1:0:1:3",
						"prefix":  uint32(64),
					},
				},
				"routes":     [][]interface{}{},
				"dns-search": []string{},
				"method":     "manual",
				"route-data": []map[string]interface{}{
					{
						"dest":     "fc00:5aa8:7160:d9eb::1",
						"prefix":   uint32(128),
						"next-hop": "fe80::1",
						"metric":   uint32(200),
					},
				},
				"dhcp-timeout": 45,
				"route-metric": 100,
				"addresses":    [][]interface{}{},
			},
			"proxy": {},
			"connection": {
				"uuid":                 "41f45675-787c-491e-a034-0363732908f7",
				"autoconnect-priority": 1,
				"autoconnect-retries":  0,
				"id":                   "vxlan",
				"interface-name":       "test_eth1.1557",
				"permissions":          []string{},
				"timestamp":            1669049774,
				"type":                 "802-3-ethernet",
			},
			"802-3-ethernet": {
				"auto-negotiate":        false,
				"mac-address-blacklist": []string{},
				"s390-options":          map[string]string{},
			},
		},
	}
	connections = append(connections, connection)

	connection = &mockNMConnection{
		settings: gonetworkmanager.ConnectionSettings{
			"ipv4": {
				"address-data": []map[string]interface{}{
					{
						"address": "203.0.113.2",
						"prefix":  uint32(24),
					},
					{
						"address": "203.0.113.3",
						"prefix":  uint32(24),
					},
				},
				"dns-search":   []string{},
				"method":       "manual",
				"gateway":      "203.0.113.1",
				"route-data":   []map[string]interface{}(nil),
				"routes":       [][]uint32{},
				"addresses":    [][]uint32{},
				"route-metric": 100,
				"dhcp-timeout": 45,
			},
			"ipv6": {
				"addr-gen-mode": 3,
				"address-data": []map[string]interface{}{
					{
						"address": "abcd:ef12:3456:10::4",
						"prefix":  uint32(64),
					},
				},
				"routes":       [][]interface{}{},
				"dns-search":   []string{},
				"method":       "manual",
				"gateway":      "abcd:ef12:3456:10::1",
				"route-data":   []map[string]interface{}(nil),
				"dhcp-timeout": 45,
				"route-metric": 100,
				"addresses":    [][]interface{}{},
			},
			"proxy": {},
			"connection": {
				"uuid":                 "2f2e2453-4f68-41b1-95c5-817276bbce9f",
				"autoconnect-priority": 1,
				"autoconnect-retries":  0,
				"id":                   "test",
				"interface-name":       "test_eth2",
				"permissions":          []string{},
				"timestamp":            1669049774,
				"type":                 "802-3-ethernet",
			},
			"802-3-ethernet": {
				"auto-negotiate":        false,
				"mac-address-blacklist": []string{},
				"s390-options":          map[string]string{},
			},
		},
	}
	connections = append(connections, connection)

	return connections, nil
}

func (s *mockNMSettings) ReloadConnections() error {
	return nil
}

func (s *mockNMSettings) GetConnectionByUUID(uuid string) (gonetworkmanager.Connection, error) {
	return nil, nil
}

func (s *mockNMSettings) AddConnection(settings gonetworkmanager.ConnectionSettings) (gonetworkmanager.Connection, error) {
	return nil, nil
}

func (s *mockNMSettings) AddConnectionUnsaved(settings gonetworkmanager.ConnectionSettings) (gonetworkmanager.Connection, error) {
	return nil, nil
}

func (s *mockNMSettings) SaveHostname(hostname string) error {
	return nil
}

func (s *mockNMSettings) GetPropertyHostname() (string, error) {
	return "", nil
}

func (s *mockNMSettings) GetPropertyCanModify() (bool, error) {
	return false, nil
}

// Validate the ifupdown configuration parser/writer functions.
func TestNetworkManager(t *testing.T) {
	// Setup test file.
	tmpDir := "/tmp/networkManager-netconfig-Test"
	testDir, err := filepath.Abs("./tests/networkManager")
	require.NoError(t, err)
	resultsDir := filepath.Join(testDir, "results")

	// Update the PATH environment variable so that our nmcli is used instead of the systems.
	pathEnv := os.Getenv("PATH")
	os.Setenv("PATH", testDir+":"+pathEnv)

	// Setup ifupdown and parse test file.
	n := new(networkManager)
	n.config = new(mockNMSettings)

	// Get the interfaces state.
	interfaces, err := n.GetInterfaces()
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 1)
	require.NoError(t, err)

	// Test setting the IP addresses on an interface.
	err = n.SetIfaceAddresses(context.Background(), "test_eth0.1556", []*net.IPNet{
		{
			IP:   net.ParseIP("1.2.3.4"),
			Mask: net.CIDRMask(24, 32),
		},
		{
			IP:   net.ParseIP("1.2.3.43"),
			Mask: net.CIDRMask(24, 32),
		},
		{
			IP:   net.ParseIP("fc00::2"),
			Mask: net.CIDRMask(64, 128),
		},
	}, net.ParseIP("1.2.3.1"), net.ParseIP("fc00::1"))
	require.NoError(t, err)

	// Test setting routes on an interface.
	err = n.SetIfaceRoutes(context.Background(), "test_eth2", []*Route{
		{
			Destination: &net.IPNet{
				IP:   net.ParseIP("abcd:ef12:3455:10::"),
				Mask: net.CIDRMask(64, 128),
			},
			Gateway: net.ParseIP("abcd:ef12:3456:10::1"),
			Metric:  100,
		},
		{
			Destination: &net.IPNet{
				IP:   net.ParseIP("10.253.2.0"),
				Mask: net.CIDRMask(24, 32),
			},
			Gateway: net.ParseIP("203.0.113.22"),
			Metric:  100,
		},
	})
	require.NoError(t, err)

	// Test setting DNS on an interface; static DNS should disable automatic DNS.
	err = n.SetIfaceDNS(context.Background(), "test_eth0", []net.IP{
		net.ParseIP("8.8.8.8"),
		net.ParseIP("1.1.1.1"),
		net.ParseIP("2001:4860:4860::8888"),
	}, []string{"example.com"})
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 1)
	require.NoError(t, err)

	// Test setting the IP addresses on an interface.
	err = n.SetIfaceAddresses(context.Background(), "test_eth0", []*net.IPNet{
		{
			IP:   net.ParseIP("1.2.10.4"),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.ParseIP("1.2.10.254"), nil)
	require.NoError(t, err)

	// Test setting routes on an interface.
	err = n.SetIfaceRoutes(context.Background(), "test_eth0.1556", []*Route{})
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	require.NoError(t, err)

	// Cleanup.
	err = os.RemoveAll(tmpDir)
	require.NoError(t, err)
}

// nmNameservers must read the modern dns-data (strings) as well as the legacy
// "dns" property (ipv4 uint32 array, ipv6 byte-array array), and nmSearchDomains
// must read dns-search. Empty groups return nothing without error.
func TestNMDNSParsing(t *testing.T) {
	// Modern dns-data + dns-search, applies to either family.
	group := map[string]any{
		"dns-data":   []string{"8.8.8.8", "1.1.1.1"},
		"dns-search": []string{"a.test", "b.test"},
	}
	got := nmNameservers(group)
	want := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}
	assert.Truef(t, equalIPs(got, want), "dns-data = %v, want %v", got, want)
	search := nmSearchDomains(group)
	assert.Falsef(t, len(search) != 2 || search[0] != "a.test" || search[1] != "b.test", "dns-search = %v, want [a.test b.test]", search)

	// Legacy ipv4 "dns" as []uint32 (decoded via uint2IP, matching addresses).
	ipv4Legacy := map[string]any{"dns": []uint32{ip2Uint(net.ParseIP("1.2.3.4"))}}
	gotV4 := nmNameservers(ipv4Legacy)
	assert.Falsef(t, len(gotV4) != 1 || !gotV4[0].Equal(net.ParseIP("1.2.3.4")), "legacy ipv4 dns = %v, want [1.2.3.4]", gotV4)

	// Legacy ipv6 "dns" as [][]byte.
	ipv6Legacy := map[string]any{"dns": [][]byte{net.ParseIP("2001:4860:4860::8888").To16()}}
	gotV6 := nmNameservers(ipv6Legacy)
	assert.Falsef(t, len(gotV6) != 1 || !gotV6[0].Equal(net.ParseIP("2001:4860:4860::8888")), "legacy ipv6 dns = %v, want [2001:4860:4860::8888]", gotV6)

	// Empty group yields nothing.
	assert.Emptyf(t, nmNameservers(map[string]any{}), "empty group dns, want empty")
	assert.Emptyf(t, nmSearchDomains(map[string]any{}), "empty group dns-search, want empty")
}

// nmConn builds a profile for the matching tests. An empty interface name or
// mac leaves that property off the profile entirely, the way NetworkManager
// reports one that is not bound by it.
func nmConn(id, uuid, iface, mac string) nmTarget {
	conn := map[string]any{"id": id, "uuid": uuid}
	if iface != "" {
		conn["interface-name"] = iface
	}
	ethernet := map[string]any{}
	if mac != "" {
		ethernet["mac-address"] = []byte(parseMAC(mac))
	}
	return nmTarget{ID: id, Settings: gonetworkmanager.ConnectionSettings{
		"connection":     conn,
		"802-3-ethernet": ethernet,
	}}
}

func parseMAC(s string) net.HardwareAddr {
	mac, _ := net.ParseMAC(s)
	return mac
}

// A profile that names the interface is bound to it, and is the whole answer
// when one exists.
func TestMatchByIfaceName(t *testing.T) {
	all := []nmTarget{
		nmConn("eth0", "uuid-eth0", "eth0", ""),
		nmConn("eth1", "uuid-eth1", "eth1", ""),
		nmConn("Wired connection 1", "uuid-wired", "", "52:54:00:34:7a:66"),
	}
	matched := matchByIfaceName(all, "eth0")
	require.Len(t, matched, 1)
	assert.Equal(t, "eth0", matched[0].ID)

	assert.Empty(t, matchByIfaceName(all, "eth2"))
}

// The fallback covers the profiles a device runs without being named by one:
// NetworkManager's default wired connection, and a profile pinned to the
// device's hardware address.
func TestMatchByDevice(t *testing.T) {
	wired := nmConn("Wired connection 1", "uuid-wired", "", "")
	pinned := nmConn("static", "uuid-static", "", "52:54:00:34:7A:66")
	other := nmConn("eth1", "uuid-eth1", "eth1", "52:54:00:34:7a:66")
	all := []nmTarget{wired, pinned, other}

	// The active profile matches even though it names nothing.
	matched := matchByDevice(all, "uuid-wired", "")
	require.Len(t, matched, 1)
	assert.Equal(t, "Wired connection 1", matched[0].ID)

	// A profile pinned to the device's address matches, case-insensitively.
	matched = matchByDevice(all, "", "52:54:00:34:7a:66")
	require.Len(t, matched, 1)
	assert.Equal(t, "static", matched[0].ID)

	// Both identifiers together match each profile once.
	matched = matchByDevice(all, "uuid-wired", "52:54:00:34:7a:66")
	require.Len(t, matched, 2)

	// A profile bound to another interface by name is never a candidate, and
	// identifiers that could not be resolved match nothing rather than
	// everything.
	assert.Empty(t, matchByDevice(all, "", ""))
}

// The hardware address a profile is pinned to is read from either the byte
// array D-Bus reports or the printed form a keyfile can surface.
func TestNMSettingsMAC(t *testing.T) {
	bytes := gonetworkmanager.ConnectionSettings{
		"802-3-ethernet": {"mac-address": []byte(parseMAC("52:54:00:34:7a:66"))},
	}
	assert.Equal(t, "52:54:00:34:7a:66", nmSettingsMAC(bytes))

	printed := gonetworkmanager.ConnectionSettings{
		"802-3-ethernet": {"mac-address": "52:54:00:34:7a:66"},
	}
	assert.Equal(t, "52:54:00:34:7a:66", nmSettingsMAC(printed))

	assert.Empty(t, nmSettingsMAC(gonetworkmanager.ConnectionSettings{"connection": {"id": "x"}}))
	assert.Empty(t, nmSettingsMAC(gonetworkmanager.ConnectionSettings{"802-3-ethernet": {"mac-address": []byte{}}}))
}
