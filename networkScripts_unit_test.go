package netconfig

import (
	"net"
	"testing"
)

// parseIPRoutes is a pure transform from raw whitespace-split route fields to
// Route structs; exercise its branches directly rather than via fixtures.
func TestParseIPRoutes(t *testing.T) {
	t.Run("full route", func(t *testing.T) {
		routes := parseIPRoutes([][]string{
			{"10.0.0.0/24", "via", "10.0.0.1", "metric", "100"},
		})
		if len(routes) != 1 {
			t.Fatalf("got %d routes, want 1", len(routes))
		}
		r := routes[0]
		if got := r.Destination.String(); got != "10.0.0.0/24" {
			t.Errorf("destination = %s, want 10.0.0.0/24", got)
		}
		if !r.Gateway.Equal(net.ParseIP("10.0.0.1")) {
			t.Errorf("gateway = %s, want 10.0.0.1", r.Gateway)
		}
		if r.Metric != 100 {
			t.Errorf("metric = %d, want 100", r.Metric)
		}
	})

	t.Run("default metric when absent", func(t *testing.T) {
		routes := parseIPRoutes([][]string{{"10.0.0.0/24", "via", "10.0.0.1"}})
		if len(routes) != 1 || routes[0].Metric != 256 {
			t.Fatalf("expected single route with default metric 256, got %+v", routes)
		}
	})

	t.Run("metric zero falls back to default", func(t *testing.T) {
		routes := parseIPRoutes([][]string{{"10.0.0.0/24", "metric", "0"}})
		if len(routes) != 1 || routes[0].Metric != 256 {
			t.Fatalf("expected default metric 256 for metric 0, got %+v", routes)
		}
	})

	t.Run("invalid metric falls back to default", func(t *testing.T) {
		routes := parseIPRoutes([][]string{{"10.0.0.0/24", "metric", "notanumber"}})
		if len(routes) != 1 || routes[0].Metric != 256 {
			t.Fatalf("expected default metric 256 for bad metric, got %+v", routes)
		}
	})

	t.Run("empty and invalid entries are skipped", func(t *testing.T) {
		routes := parseIPRoutes([][]string{
			{},                                       // empty: skipped
			{"not-a-cidr"},                           // invalid CIDR: skipped
			{"10.0.0.0/24", "via", "nope"},           // bad gateway: skipped
			{"192.168.0.0/16", "via", "192.168.0.1"}, // valid
		})
		if len(routes) != 1 {
			t.Fatalf("got %d routes, want 1", len(routes))
		}
		if got := routes[0].Destination.String(); got != "192.168.0.0/16" {
			t.Errorf("destination = %s, want 192.168.0.0/16", got)
		}
	})
}

// ParseIP derives a *net.IPNet from network-scripts style key/value config.
func TestNetworkScriptsParseIP(t *testing.T) {
	ns := &networkScripts{}

	t.Run("missing IPADDR returns nil", func(t *testing.T) {
		if got := ns.ParseIP(map[string]string{}, ""); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("empty IPADDR returns nil", func(t *testing.T) {
		if got := ns.ParseIP(map[string]string{"IPADDR": ""}, ""); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("explicit prefix", func(t *testing.T) {
		got := ns.ParseIP(map[string]string{"IPADDR": "192.168.1.5", "PREFIX": "24"}, "")
		if got == nil {
			t.Fatal("got nil")
		}
		if !got.IP.Equal(net.ParseIP("192.168.1.5")) {
			t.Errorf("IP = %s, want 192.168.1.5", got.IP)
		}
		if ones, _ := got.Mask.Size(); ones != 24 {
			t.Errorf("prefix = %d, want 24", ones)
		}
	})

	t.Run("prefix derived from netmask", func(t *testing.T) {
		got := ns.ParseIP(map[string]string{"IPADDR": "10.1.2.3", "NETMASK": "255.255.255.0"}, "")
		if got == nil {
			t.Fatal("got nil")
		}
		if ones, _ := got.Mask.Size(); ones != 24 {
			t.Errorf("prefix = %d, want 24 (from netmask)", ones)
		}
	})

	t.Run("defaults to /16 with no prefix or netmask", func(t *testing.T) {
		got := ns.ParseIP(map[string]string{"IPADDR": "10.1.2.3"}, "")
		if got == nil {
			t.Fatal("got nil")
		}
		if ones, _ := got.Mask.Size(); ones != 16 {
			t.Errorf("prefix = %d, want default 16", ones)
		}
	})

	t.Run("indexed keys", func(t *testing.T) {
		cfg := map[string]string{"IPADDR0": "172.16.0.9", "PREFIX0": "30"}
		got := ns.ParseIP(cfg, "0")
		if got == nil {
			t.Fatal("got nil")
		}
		if !got.IP.Equal(net.ParseIP("172.16.0.9")) {
			t.Errorf("IP = %s, want 172.16.0.9", got.IP)
		}
		if ones, _ := got.Mask.Size(); ones != 30 {
			t.Errorf("prefix = %d, want 30", ones)
		}
	})

	t.Run("invalid address returns nil", func(t *testing.T) {
		if got := ns.ParseIP(map[string]string{"IPADDR": "not-an-ip", "PREFIX": "24"}, ""); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}
