package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

// cidr is a terse *net.IPNet literal for the tests below.
func cidr(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(s)
	require.NoError(t, err)
	ipnet.IP = ip
	return ipnet
}

// A netplan interface must report and record each family's client
// independently, and must not grow a dhcp4/dhcp6 key that was never there.
func TestNetplanSetDHCP(t *testing.T) {
	t.Run("reads absent keys as off", func(t *testing.T) {
		dhcp4, dhcp6 := (&npInterface{}).dhcpState()
		assert.False(t, dhcp4)
		assert.False(t, dhcp6)
	})

	t.Run("enables one family without touching the other", func(t *testing.T) {
		c := npInterface{}
		c.setDHCP(true, false)
		require.NotNil(t, c.DHCP4)
		assert.True(t, *c.DHCP4)
		assert.Nil(t, c.DHCP6, "dhcp6 was absent and stays absent when disabled")
	})

	t.Run("disabling drops that family's overrides only", func(t *testing.T) {
		c := npInterface{
			DHCP4:          boolPtr(true),
			DHCP6:          boolPtr(true),
			DHCP4Overrides: map[string]any{"use-dns": false},
			DHCP6Overrides: map[string]any{"use-dns": false},
		}
		c.setDHCP(false, true)
		assert.False(t, *c.DHCP4)
		assert.Nil(t, c.DHCP4Overrides, "overrides of a stopped client are dead config")
		assert.True(t, *c.DHCP6)
		assert.NotNil(t, c.DHCP6Overrides)
	})

	t.Run("disabling an absent key does not write it", func(t *testing.T) {
		c := npInterface{}
		c.setDHCP(false, false)
		assert.Nil(t, c.DHCP4)
		assert.Nil(t, c.DHCP6)
	})

	t.Run("round trips through dhcpState", func(t *testing.T) {
		c := npInterface{}
		c.setDHCP(true, true)
		dhcp4, dhcp6 := c.dhcpState()
		assert.True(t, dhcp4)
		assert.True(t, dhcp6)
	})
}

func TestCloudInitSetDHCP(t *testing.T) {
	c := ciInterface{DHCP4: boolPtr(true), DHCP6Overrides: map[string]any{"use-dns": false}}
	c.setDHCP(false, false)
	require.NotNil(t, c.DHCP4)
	assert.False(t, *c.DHCP4)
	assert.Nil(t, c.DHCP6, "absent stays absent")
	assert.Nil(t, c.DHCP6Overrides)
}

func TestParseNetworkdDHCP(t *testing.T) {
	tests := []struct {
		value        string
		dhcp4, dhcp6 bool
	}{
		{value: "yes", dhcp4: true, dhcp6: true},
		{value: "true", dhcp4: true, dhcp6: true},
		{value: "both", dhcp4: true, dhcp6: true},
		{value: " YES ", dhcp4: true, dhcp6: true},
		{value: "ipv4", dhcp4: true},
		{value: "v4", dhcp4: true},
		{value: "ipv6", dhcp6: true},
		{value: "no"},
		{value: "none"},
		{value: ""},
		{value: "garbage"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			dhcp4, dhcp6 := parseNetworkdDHCP(tt.value)
			assert.Equal(t, tt.dhcp4, dhcp4, "dhcp4")
			assert.Equal(t, tt.dhcp6, dhcp6, "dhcp6")
		})
	}
}

func TestFormatNetworkdDHCP(t *testing.T) {
	tests := []struct {
		name         string
		dhcp4, dhcp6 bool
		value        string
		keep         bool
	}{
		{name: "both", dhcp4: true, dhcp6: true, value: "yes", keep: true},
		{name: "v4", dhcp4: true, value: "ipv4", keep: true},
		{name: "v6", dhcp6: true, value: "ipv6", keep: true},
		{name: "neither", value: "", keep: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, keep := formatNetworkdDHCP(tt.dhcp4, tt.dhcp6)
			assert.Equal(t, tt.keep, keep)
			assert.Equal(t, tt.value, value)
		})
	}
}

// networkdDHCPValue builds a [Network] section carrying the given DHCP= value
// ("" for no key at all), runs setNetworkdDHCP over it, and reports the
// resulting value plus whether the key survived.
func networkdDHCPValue(t *testing.T, start string, dhcp4, dhcp6 bool) (string, bool) {
	t.Helper()
	cfg := ini.Empty()
	sec, err := cfg.NewSection("Network")
	require.NoError(t, err)
	if start != "" {
		_, err = sec.NewKey("DHCP", start)
		require.NoError(t, err)
	}

	require.NoError(t, setNetworkdDHCP(sec, dhcp4, dhcp6))

	if !sec.HasKey("DHCP") {
		return "", false
	}
	return sec.Key("DHCP").String(), true
}

func TestSetNetworkdDHCP(t *testing.T) {
	t.Run("narrows a dual-stack lease to one family", func(t *testing.T) {
		value, present := networkdDHCPValue(t, "yes", false, true)
		require.True(t, present)
		assert.Equal(t, "ipv6", value)
	})

	t.Run("removes the key when no family is left", func(t *testing.T) {
		_, present := networkdDHCPValue(t, "ipv4", false, false)
		assert.False(t, present, "DHCP= should be removed, not written as no")
	})

	t.Run("creates the key on a config that lacked it", func(t *testing.T) {
		value, present := networkdDHCPValue(t, "", true, false)
		require.True(t, present)
		assert.Equal(t, "ipv4", value)
	})

	t.Run("leaves an absent key absent when disabling", func(t *testing.T) {
		_, present := networkdDHCPValue(t, "", false, false)
		assert.False(t, present)
	})
}

// A .network file must round trip through SetIfaceDHCP and GetInterfaces, and
// SetIfaceAddresses must not disturb the DHCP key on the way past.
func TestNetworkdSetIfaceDHCP(t *testing.T) {
	newNetworkdDir := func(t *testing.T, body string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "eth0.network")
		require.NoError(t, os.WriteFile(path, []byte(body), 0644))
		return dir, path
	}

	t.Run("enables a family and reads it back", func(t *testing.T) {
		dir, path := newNetworkdDir(t, "[Match]\nName=eth0\n\n[Network]\nAddress=1.2.3.4/24\n")

		nd, err := readNetworkdConfigDirectory(dir)
		require.NoError(t, err)
		require.NoError(t, nd.SetIfaceDHCP(context.Background(), "eth0", true, false))

		cfg, err := ini.Load(path)
		require.NoError(t, err)
		assert.Equal(t, "ipv4", cfg.Section("Network").Key("DHCP").String())
		assert.Equal(t, "1.2.3.4/24", cfg.Section("Network").Key("Address").String(),
			"the static address must survive enabling DHCP")
	})

	t.Run("a DHCP-only network still reports its state", func(t *testing.T) {
		dir, _ := newNetworkdDir(t, "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n")

		nd, err := readNetworkdConfigDirectory(dir)
		require.NoError(t, err)
		ifaces, err := nd.GetInterfaces()
		require.NoError(t, err)
		require.Len(t, ifaces, 1)
		assert.True(t, ifaces[0].DHCP4, "a network with no Address must still report DHCP")
		assert.True(t, ifaces[0].DHCP6)
	})

	t.Run("setting addresses leaves DHCP alone", func(t *testing.T) {
		dir, path := newNetworkdDir(t, "[Match]\nName=eth0\n\n[Network]\nDHCP=yes\n")

		nd, err := readNetworkdConfigDirectory(dir)
		require.NoError(t, err)
		err = nd.SetIfaceAddresses(context.Background(), "eth0",
			[]*net.IPNet{cidr(t, "1.2.3.4/24")}, net.ParseIP("1.2.3.1"), nil)
		require.NoError(t, err)

		cfg, err := ini.Load(path)
		require.NoError(t, err)
		assert.Equal(t, "yes", cfg.Section("Network").Key("DHCP").String(),
			"adding a static address must not disable DHCP")
		assert.Equal(t, "1.2.3.4/24", cfg.Section("Network").Key("Address").String())
	})
}

func TestNSDHCPState(t *testing.T) {
	tests := []struct {
		name         string
		config       map[string]string
		dhcp4, dhcp6 bool
	}{
		{name: "empty", config: map[string]string{}},
		{name: "static", config: map[string]string{"BOOTPROTO": "none"}},
		{name: "dhcp", config: map[string]string{"BOOTPROTO": "dhcp"}, dhcp4: true},
		{name: "uppercase dhcp", config: map[string]string{"BOOTPROTO": "DHCP"}, dhcp4: true},
		{name: "bootp is dynamic", config: map[string]string{"BOOTPROTO": "bootp"}, dhcp4: true},
		{name: "dhcpv6c", config: map[string]string{"DHCPV6C": "yes"}, dhcp6: true},
		{
			name:   "both",
			config: map[string]string{"BOOTPROTO": "dhcp", "DHCPV6C": "yes"},
			dhcp4:  true, dhcp6: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dhcp4, dhcp6 := nsDHCPState(tt.config)
			assert.Equal(t, tt.dhcp4, dhcp4, "dhcp4")
			assert.Equal(t, tt.dhcp6, dhcp6, "dhcp6")
		})
	}
}

func TestNetworkScriptsSetIfaceDHCP(t *testing.T) {
	// Re-read the ifcfg file from disk so we assert on what was persisted.
	readConfig := func(t *testing.T, dir string) map[string]string {
		t.Helper()
		ns, err := newNetworkScriptsWithConfig(dir)
		require.NoError(t, err)
		require.Len(t, ns.Interfaces, 1)
		require.Len(t, ns.Interfaces[0].IFFiles, 1)
		return ns.Interfaces[0].IFFiles[0].Config
	}

	newDir := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ifcfg-eth0"), []byte(body), 0644))
		return dir
	}

	t.Run("enabling ipv4 keeps the static address", func(t *testing.T) {
		dir := newDir(t, "DEVICE=eth0\nBOOTPROTO=none\nIPADDR0=1.2.3.4\nPREFIX0=24\n")

		ns, err := newNetworkScriptsWithConfig(dir)
		require.NoError(t, err)
		require.NoError(t, ns.SetIfaceDHCP(context.Background(), "eth0", true, false))

		config := readConfig(t, dir)
		assert.Equal(t, "dhcp", config["BOOTPROTO"])
		assert.Equal(t, "1.2.3.4", config["IPADDR0"], "the static address must survive")
	})

	t.Run("disabling ipv4 writes none and drops the dhclient option", func(t *testing.T) {
		dir := newDir(t, "DEVICE=eth0\nBOOTPROTO=dhcp\nPERSISTENT_DHCLIENT=1\n")

		ns, err := newNetworkScriptsWithConfig(dir)
		require.NoError(t, err)
		require.NoError(t, ns.SetIfaceDHCP(context.Background(), "eth0", false, false))

		config := readConfig(t, dir)
		assert.Equal(t, "none", config["BOOTPROTO"])
		_, ok := config["PERSISTENT_DHCLIENT"]
		assert.False(t, ok)
	})

	t.Run("the two families are independent", func(t *testing.T) {
		dir := newDir(t, "DEVICE=eth0\nBOOTPROTO=dhcp\nDHCPV6C=yes\n")

		ns, err := newNetworkScriptsWithConfig(dir)
		require.NoError(t, err)
		require.NoError(t, ns.SetIfaceDHCP(context.Background(), "eth0", false, true))

		config := readConfig(t, dir)
		assert.Equal(t, "none", config["BOOTPROTO"])
		assert.Equal(t, "yes", config["DHCPV6C"])
		assert.Equal(t, "yes", config["IPV6INIT"], "DHCPv6 needs IPv6 turned on")
	})

	t.Run("adding an address leaves BOOTPROTO alone", func(t *testing.T) {
		dir := newDir(t, "DEVICE=eth0\nBOOTPROTO=dhcp\n")

		ns, err := newNetworkScriptsWithConfig(dir)
		require.NoError(t, err)
		err = ns.SetIfaceAddresses(context.Background(), "eth0",
			[]*net.IPNet{cidr(t, "1.2.3.4/24")}, nil, nil)
		require.NoError(t, err)

		config := readConfig(t, dir)
		assert.Equal(t, "dhcp", config["BOOTPROTO"],
			"a static address may coexist with a lease; only SetDHCP turns it off")
		assert.Equal(t, "1.2.3.4", config["IPADDR0"])
	})

	t.Run("reads the state back through GetInterfaces", func(t *testing.T) {
		dir := newDir(t, "DEVICE=eth0\nBOOTPROTO=dhcp\nDHCPV6C=yes\n")

		ns, err := newNetworkScriptsWithConfig(dir)
		require.NoError(t, err)
		ifaces, err := ns.GetInterfaces()
		require.NoError(t, err)
		require.Len(t, ifaces, 1)
		assert.True(t, ifaces[0].DHCP4)
		assert.True(t, ifaces[0].DHCP6)
	})
}

func TestIfUpDownSetDHCP(t *testing.T) {
	t.Run("converts the stanza method for its own family", func(t *testing.T) {
		iface := &ifInterface{Name: "eth0", Mode: "inet static"}
		require.NoError(t, iface.setDHCP(true, false))
		assert.Equal(t, "inet dhcp", iface.Mode)
		assert.True(t, iface.isDHCP)

		require.NoError(t, iface.setDHCP(false, false))
		assert.Equal(t, "inet static", iface.Mode)
		assert.False(t, iface.isDHCP)
	})

	t.Run("inet6 stanza follows dhcp6", func(t *testing.T) {
		iface := &ifInterface{Name: "eth0", Mode: "inet6 static"}
		require.NoError(t, iface.setDHCP(false, true))
		assert.Equal(t, "inet6 dhcp", iface.Mode)
		assert.True(t, iface.isDHCP)
	})

	t.Run("a stanza-less interface gets one", func(t *testing.T) {
		iface := &ifInterface{Name: "eth0"}
		require.NoError(t, iface.setDHCP(true, false))
		assert.Equal(t, "inet dhcp", iface.Mode)
	})

	t.Run("errors rather than silently ignoring the other family", func(t *testing.T) {
		iface := &ifInterface{Name: "eth0", Mode: "inet static"}
		err := iface.setDHCP(false, true)
		assert.ErrorContains(t, err, "other family")
		assert.Equal(t, "inet static", iface.Mode, "the stanza must be untouched on error")
	})

	t.Run("errors on both families at once", func(t *testing.T) {
		iface := &ifInterface{Name: "eth0"}
		assert.ErrorContains(t, iface.setDHCP(true, true), "both families")
	})

	t.Run("refuses methods it cannot convert", func(t *testing.T) {
		for _, method := range []string{"loopback", "ppp"} {
			iface := &ifInterface{Name: "lo", Mode: "inet " + method}
			assert.ErrorContains(t, iface.setDHCP(true, false), method)
		}
	})

	t.Run("dhcpState reports the stanza's family only", func(t *testing.T) {
		dhcp4, dhcp6 := (&ifInterface{Mode: "inet dhcp", isDHCP: true}).dhcpState()
		assert.True(t, dhcp4)
		assert.False(t, dhcp6)

		dhcp4, dhcp6 = (&ifInterface{Mode: "inet6 dhcp", isDHCP: true}).dhcpState()
		assert.False(t, dhcp4)
		assert.True(t, dhcp6)

		dhcp4, dhcp6 = (&ifInterface{Mode: "inet static"}).dhcpState()
		assert.False(t, dhcp4)
		assert.False(t, dhcp6)
	})
}

// Switching an ifupdown interface to DHCP must drop the static addressing the
// stanza carried, since a "dhcp" stanza has no address option to hold it.
func TestIfUpDownSetIfaceDHCPPersists(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "interfaces")
	config := "auto eth0\niface eth0 inet static\n\taddress 1.2.3.4/24\n\tgateway 1.2.3.1\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(config), 0644))

	i := &ifUpDown{BaseConfig: cfgPath, BackupDir: filepath.Join(dir, "backup")}
	require.NoError(t, os.Mkdir(i.BackupDir, 0755))
	require.NoError(t, i.ReadFile(cfgPath))
	require.NoError(t, i.SetIfaceDHCP(context.Background(), "eth0", true, false))

	// Re-read from disk to confirm what was persisted.
	reread := &ifUpDown{BaseConfig: cfgPath, BackupDir: i.BackupDir}
	require.NoError(t, reread.ReadFile(cfgPath))
	require.Len(t, reread.Interfaces, 1)
	eth0 := reread.Interfaces[0]
	assert.Equal(t, "inet dhcp", eth0.Mode)
	assert.True(t, eth0.isDHCP)
	assert.Empty(t, eth0.Addresses, "a dhcp stanza cannot carry a static address")
	assert.Nil(t, eth0.Gateway4)

	// And the interface reports itself as DHCPv4.
	ifaces, err := reread.GetInterfaces()
	require.NoError(t, err)
	require.Len(t, ifaces, 1)
	assert.True(t, ifaces[0].DHCP4)
	assert.False(t, ifaces[0].DHCP6)
}

// SetIfaceAddresses must leave netplan's dhcp4 alone: a static address and a
// lease coexist, and only SetIfaceDHCP decides otherwise.
func TestNetplanSetIfaceAddressesKeepsDHCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "01-netcfg.yaml")
	config := "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n"
	require.NoError(t, os.WriteFile(path, []byte(config), 0644))

	np, err := readNetplanConfigDirectory(dir)
	require.NoError(t, err)
	err = np.SetIfaceAddresses(context.Background(), "eth0",
		[]*net.IPNet{cidr(t, "1.2.3.4/24")}, net.ParseIP("1.2.3.1"), nil)
	require.NoError(t, err)

	reread, err := readNetplanConfigDirectory(dir)
	require.NoError(t, err)
	require.Len(t, reread.configs, 1)
	eth0, ok := reread.configs[0].Network.Ethernets["eth0"]
	require.True(t, ok)
	require.NotNil(t, eth0.DHCP4)
	assert.True(t, *eth0.DHCP4, "adding a static address must not disable DHCP")
	assert.Equal(t, []string{"1.2.3.4/24"}, eth0.Addresses)
}

// SetIfaceDHCP must write netplan's dhcp4/dhcp6 and leave the addresses alone.
func TestNetplanSetIfaceDHCPPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "01-netcfg.yaml")
	config := "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses:\n        - 1.2.3.4/24\n"
	require.NoError(t, os.WriteFile(path, []byte(config), 0644))

	np, err := readNetplanConfigDirectory(dir)
	require.NoError(t, err)
	require.NoError(t, np.SetIfaceDHCP(context.Background(), "eth0", true, false))

	reread, err := readNetplanConfigDirectory(dir)
	require.NoError(t, err)
	eth0, ok := reread.configs[0].Network.Ethernets["eth0"]
	require.True(t, ok)
	require.NotNil(t, eth0.DHCP4)
	assert.True(t, *eth0.DHCP4)
	assert.Nil(t, eth0.DHCP6, "the untouched family must not gain a key")
	assert.Equal(t, []string{"1.2.3.4/24"}, eth0.Addresses,
		"static addresses coexist with a lease")

	// And it reads back through GetInterfaces.
	ifaces, err := reread.GetInterfaces()
	require.NoError(t, err)
	require.Len(t, ifaces, 1)
	assert.True(t, ifaces[0].DHCP4)
	assert.False(t, ifaces[0].DHCP6)
}

// newTestCloudInit builds a cloudInit over a temporary network config file, so
// SetIfaceDHCP has somewhere real to Save to.
func newTestCloudInit(t *testing.T, config string) *cloudInit {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "network.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0644))
	ci, err := newCloudInitWith(configPath, filepath.Join(dir, "nothing.json"), filepath.Join(dir, "cloud.cfg.d"))
	require.NoError(t, err)
	return ci
}

// cloud-init's v1 schema encodes DHCP as a subnet type. Enabling a client must
// add that subnet without disturbing the static subnet beside it.
func TestCloudInitSetIfaceDHCPV1(t *testing.T) {
	ci := newTestCloudInit(t, `network:
  version: 1
  config:
    - type: physical
      name: eth0
      subnets:
        - type: dhcp
        - type: static
          address: 1.2.3.4/24
          gateway: 1.2.3.1
`)

	// Turning IPv4 off and IPv6 on must replace the dhcp subnet with a dhcp6
	// one and leave the static subnet in place.
	require.NoError(t, ci.SetIfaceDHCP(context.Background(), "eth0", false, true))
	subnets := ci.Network.Configs[0].Subnets
	require.Len(t, subnets, 2)
	assert.Equal(t, "dhcp6", subnets[0].Type)
	assert.Equal(t, "static", subnets[1].Type)
	assert.Equal(t, "1.2.3.4/24", subnets[1].Address)

	ifaces, err := ci.GetInterfaces()
	require.NoError(t, err)
	require.Len(t, ifaces, 1)
	assert.False(t, ifaces[0].DHCP4)
	assert.True(t, ifaces[0].DHCP6)
}

// The v1 reader must recognise every spelling of a DHCP subnet.
func TestCloudInitV1DHCPSubnetTypes(t *testing.T) {
	for _, tt := range []struct {
		subnetType   string
		dhcp4, dhcp6 bool
	}{
		{subnetType: "dhcp", dhcp4: true},
		{subnetType: "dhcp4", dhcp4: true},
		{subnetType: "dhcp6", dhcp6: true},
		{subnetType: "ipv6_dhcpv6-stateful", dhcp6: true},
		{subnetType: "static"},
	} {
		t.Run(tt.subnetType, func(t *testing.T) {
			ci := newTestCloudInit(t, `network:
  version: 1
  config:
    - type: physical
      name: eth0
      subnets:
        - type: `+tt.subnetType+`
          address: 1.2.3.4/24
`)
			ifaces, err := ci.GetInterfaces()
			require.NoError(t, err)
			require.Len(t, ifaces, 1)
			assert.Equal(t, tt.dhcp4, ifaces[0].DHCP4, "dhcp4")
			assert.Equal(t, tt.dhcp6, ifaces[0].DHCP6, "dhcp6")
		})
	}
}

// The v2 schema keeps DHCP in dhcp4/dhcp6 keys beside the static addresses.
func TestCloudInitSetIfaceDHCPV2(t *testing.T) {
	ci := newTestCloudInit(t, `network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 1.2.3.4/24
`)
	require.NoError(t, ci.SetIfaceDHCP(context.Background(), "eth0", true, false))

	eth0, ok := ci.Network.Ethernets["eth0"]
	require.True(t, ok)
	require.NotNil(t, eth0.DHCP4)
	assert.True(t, *eth0.DHCP4)
	assert.Nil(t, eth0.DHCP6, "the untouched family must not gain a key")
	assert.Equal(t, []string{"1.2.3.4/24"}, eth0.Addresses)
}

func TestNMConnectionDHCPState(t *testing.T) {
	tests := []struct {
		name             string
		method4, method6 string
		dhcp4, dhcp6     bool
	}{
		{name: "auto is dhcp", method4: "auto", method6: "auto", dhcp4: true, dhcp6: true},
		{name: "manual is static", method4: "manual", method6: "manual"},
		{name: "ipv6 dhcp method", method4: "manual", method6: "dhcp", dhcp6: true},
		{name: "disabled", method4: "disabled", method6: "link-local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &nmConnection{Method4: tt.method4, Method6: tt.method6}
			dhcp4, dhcp6 := conn.dhcpState()
			assert.Equal(t, tt.dhcp4, dhcp4, "dhcp4")
			assert.Equal(t, tt.dhcp6, dhcp6, "dhcp6")
		})
	}
}

// Turning a lease off must leave behind a method that still serves whatever
// static addresses the connection holds, and not strand IPv6 with no address.
func TestNMStaticMethod(t *testing.T) {
	assert.Equal(t, "manual", nmStaticMethod4(true))
	assert.Equal(t, "disabled", nmStaticMethod4(false))
	assert.Equal(t, "manual", nmStaticMethod6(true))
	assert.Equal(t, "link-local", nmStaticMethod6(false))
}

// applyIfaceDHCP reports whether any backend persisted the change, which is what
// SetDHCP relies on before asking the running system for a lease.
func TestApplyIfaceDHCP(t *testing.T) {
	t.Run("reports true when one backend succeeds", func(t *testing.T) {
		failing := &fakeIfaceBackend{err: assert.AnError}
		ok := &fakeIfaceBackend{}
		applied := applyIfaceDHCP(context.Background(), []namedIfaceBackend{
			{name: "broken", backend: failing},
			{name: "good", backend: ok},
		}, "eth0", true, false)

		assert.True(t, applied)
		assert.Equal(t, 1, failing.dhcpCalls, "a failing backend must not stop the others")
		assert.Equal(t, 1, ok.dhcpCalls)
		assert.True(t, ok.lastDHCP4)
		assert.False(t, ok.lastDHCP6)
	})

	t.Run("reports false when every backend fails", func(t *testing.T) {
		applied := applyIfaceDHCP(context.Background(), []namedIfaceBackend{
			{name: "broken", backend: &fakeIfaceBackend{err: assert.AnError}},
		}, "eth0", true, true)
		assert.False(t, applied)
	})

	t.Run("reports false with no backends at all", func(t *testing.T) {
		assert.False(t, applyIfaceDHCP(context.Background(), nil, "eth0", true, true))
	})
}

// renewDHCPOnBackends must skip backends that cannot reconfigure the running
// system (cloud-init) rather than erroring on them.
func TestRenewDHCPOnBackends(t *testing.T) {
	renewer := &fakeRenewerBackend{}
	backends := []namedIfaceBackend{
		{name: "cloud-init", backend: &fakeIfaceBackend{}}, // no renewDHCP method
		{name: "netplan", backend: renewer},
	}
	renewDHCPOnBackends(context.Background(), backends, "eth0")
	assert.Equal(t, 1, renewer.renewCalls)
	assert.Equal(t, "eth0", renewer.lastIface)
}

// fakeRenewerBackend is a file backend that can also reconfigure the running
// system, satisfying both ifaceBackend and dhcpRenewer.
type fakeRenewerBackend struct {
	fakeIfaceBackend
	renewCalls int
	lastIface  string
	renewErr   error
}

func (f *fakeRenewerBackend) renewDHCP(_ context.Context, iface string) error {
	f.renewCalls++
	f.lastIface = iface
	return f.renewErr
}
