package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseIPRoutes is a pure transform from raw whitespace-split route fields to
// Route structs; exercise its branches directly rather than via fixtures.
func TestParseIPRoutes(t *testing.T) {
	t.Run("full route", func(t *testing.T) {
		routes := parseIPRoutes([][]string{
			{"10.0.0.0/24", "via", "10.0.0.1", "metric", "100"},
		})
		require.Len(t, routes, 1)
		r := routes[0]
		assert.Equal(t, "10.0.0.0/24", r.Destination.String())
		assert.True(t, r.Gateway.Equal(net.ParseIP("10.0.0.1")))
		assert.Equal(t, 100, r.Metric)
	})

	t.Run("default metric when absent", func(t *testing.T) {
		routes := parseIPRoutes([][]string{{"10.0.0.0/24", "via", "10.0.0.1"}})
		require.Len(t, routes, 1)
		assert.Equal(t, 256, routes[0].Metric)
	})

	t.Run("metric zero falls back to default", func(t *testing.T) {
		routes := parseIPRoutes([][]string{{"10.0.0.0/24", "metric", "0"}})
		require.Len(t, routes, 1)
		assert.Equal(t, 256, routes[0].Metric)
	})

	t.Run("invalid metric falls back to default", func(t *testing.T) {
		routes := parseIPRoutes([][]string{{"10.0.0.0/24", "metric", "notanumber"}})
		require.Len(t, routes, 1)
		assert.Equal(t, 256, routes[0].Metric)
	})

	t.Run("empty and invalid entries are skipped", func(t *testing.T) {
		routes := parseIPRoutes([][]string{
			{},                                       // empty: skipped
			{"not-a-cidr"},                           // invalid CIDR: skipped
			{"10.0.0.0/24", "via", "nope"},           // bad gateway: skipped
			{"192.168.0.0/16", "via", "192.168.0.1"}, // valid
		})
		require.Len(t, routes, 1)
		assert.Equal(t, "192.168.0.0/16", routes[0].Destination.String())
	})
}

// ParseIP derives a *net.IPNet from network-scripts style key/value config.
func TestNetworkScriptsParseIP(t *testing.T) {
	ns := &networkScripts{}

	t.Run("missing IPADDR returns nil", func(t *testing.T) {
		assert.Nil(t, ns.ParseIP(map[string]string{}, ""))
	})

	t.Run("empty IPADDR returns nil", func(t *testing.T) {
		assert.Nil(t, ns.ParseIP(map[string]string{"IPADDR": ""}, ""))
	})

	t.Run("explicit prefix", func(t *testing.T) {
		got := ns.ParseIP(map[string]string{"IPADDR": "192.168.1.5", "PREFIX": "24"}, "")
		require.NotNil(t, got)
		assert.True(t, got.IP.Equal(net.ParseIP("192.168.1.5")))
		ones, _ := got.Mask.Size()
		assert.Equal(t, 24, ones)
	})

	t.Run("prefix derived from netmask", func(t *testing.T) {
		got := ns.ParseIP(map[string]string{"IPADDR": "10.1.2.3", "NETMASK": "255.255.255.0"}, "")
		require.NotNil(t, got)
		ones, _ := got.Mask.Size()
		assert.Equal(t, 24, ones)
	})

	t.Run("defaults to /16 with no prefix or netmask", func(t *testing.T) {
		got := ns.ParseIP(map[string]string{"IPADDR": "10.1.2.3"}, "")
		require.NotNil(t, got)
		ones, _ := got.Mask.Size()
		assert.Equal(t, 16, ones)
	})

	t.Run("indexed keys", func(t *testing.T) {
		cfg := map[string]string{"IPADDR0": "172.16.0.9", "PREFIX0": "30"}
		got := ns.ParseIP(cfg, "0")
		require.NotNil(t, got)
		assert.True(t, got.IP.Equal(net.ParseIP("172.16.0.9")))
		ones, _ := got.Mask.Size()
		assert.Equal(t, 30, ones)
	})

	t.Run("invalid address returns nil", func(t *testing.T) {
		assert.Nil(t, ns.ParseIP(map[string]string{"IPADDR": "not-an-ip", "PREFIX": "24"}, ""))
	})
}

// TestNetworkScriptsKeepsLayout writes addresses into an ifcfg file laid out as
// InterWorx leaves one on CentOS 6: quoted values, a link-local IPV6ADDR, an
// empty IPV6ADDR_SECONDARIES and #IWORX comments. Unchanged lines stay as
// written and new keys follow them.
func TestNetworkScriptsKeepsLayout(t *testing.T) {
	dir := t.TempDir()
	orig := `# Managed by provisioning.
DEVICE="em1"
BOOTPROTO="static"
BROADCAST="192.0.2.255"
GATEWAY="192.0.2.1"
IPADDR="192.0.2.10"
NETMASK="255.255.255.0"
ONBOOT="yes"

IPV6INIT=yes
IPV6ADDR=fe80::1/64
IPV6ADDR_SECONDARIES=""
#IWORX_IPV6="fe80::1/64"
#IWORX_LAST_EDIT="2024-10-29 23:50:08"
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ifcfg-em1"), []byte(orig), 0644))
	ns, err := newNetworkScriptsWithConfig(dir)
	require.NoError(t, err)

	addrs := []*net.IPNet{
		{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
		{IP: net.ParseIP("192.0.2.77"), Mask: net.CIDRMask(32, 32)},
	}
	require.NoError(t, ns.SetIfaceAddresses(context.Background(), "em1", addrs, net.ParseIP("192.0.2.1"), nil))
	got, err := os.ReadFile(filepath.Join(dir, "ifcfg-em1"))
	require.NoError(t, err)
	assert.Equal(t, orig+`BROADCAST1=192.0.2.77
IPADDR1=192.0.2.77
NETMASK1=255.255.255.255
PREFIX=24
PREFIX1=32
`, string(got))

	// A global IPv6 address becomes IPV6ADDR, and the link-local one moves to
	// the secondaries in the line's quotes.
	addrs = append(addrs[:1], &net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)})
	require.NoError(t, ns.SetIfaceAddresses(context.Background(), "em1", addrs, net.ParseIP("192.0.2.1"), nil))
	got, err = os.ReadFile(filepath.Join(dir, "ifcfg-em1"))
	require.NoError(t, err)
	assert.Contains(t, string(got), "IPV6ADDR=2001:db8::10/64\nIPV6ADDR_SECONDARIES=\"fe80::1/64\"\n#IWORX_IPV6=")
	assert.NotContains(t, string(got), "IPADDR1")
}

// TestIfcfgQuote keeps a value in its line's quotes, and quotes a new value
// only when the shell would split or expand it.
func TestIfcfgQuote(t *testing.T) {
	tests := []struct {
		val, prev, want string
	}{
		{"yes", `"no"`, `"yes"`},
		{"yes", `'no'`, `'yes'`},
		{"it's", `'no'`, `"it's"`},
		{"yes", "no", "yes"},
		{"yes", "", "yes"},
		{"example.com maas", "", `"example.com maas"`},
		{`say "hi"`, "", `"say \"hi\""`},
		{"$HOME", "", `"$HOME"`},
		{"", "", ""},
		{"", `""`, `""`},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, ifcfgQuote(tt.val, tt.prev), "ifcfgQuote(%q, %q)", tt.val, tt.prev)
	}
}

// TestRenderIfcfgMultiline writes a file with a value quoted across lines
// fresh, since its lines can't be rewritten one at a time.
func TestRenderIfcfgMultiline(t *testing.T) {
	orig := "DEVICE=eth0\nNAME=\"two\nlines\"\n"
	got := renderIfcfg([]byte(orig), map[string]string{"DEVICE": "eth0", "IPADDR": "192.0.2.10"})
	assert.Equal(t, "DEVICE=eth0\nIPADDR=192.0.2.10\n", string(got))
}
