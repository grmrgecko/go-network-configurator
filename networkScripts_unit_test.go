package netconfig

import (
	"net"
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
