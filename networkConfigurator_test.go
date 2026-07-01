package netconfig

import (
	"context"
	"errors"
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}

func TestRouteString(t *testing.T) {
	r := &Route{
		Destination: mustCIDR(t, "10.0.0.0/24"),
		Gateway:     net.ParseIP("10.0.0.1"),
		Metric:      100,
	}
	if got, want := r.String(), "10.0.0.0/24 via 10.0.0.1 metric 100"; got != want {
		t.Errorf("Route.String() = %q, want %q", got, want)
	}
}

func TestInterfaceString(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	iface := &Interface{
		Name:      "eth0",
		MAC:       mac,
		Addresses: []*net.IPNet{mustCIDR(t, "192.168.1.10/24")},
		Gateway4:  net.ParseIP("192.168.1.1"),
		Routes: []*Route{
			{Destination: mustCIDR(t, "10.0.0.0/24"), Gateway: net.ParseIP("10.0.0.1"), Metric: 5},
		},
	}
	got := iface.String()
	want := "Name: eth0 MAC: 00:11:22:33:44:55 Addresses: [192.168.1.0/24] Gateway4: 192.168.1.1 Gateway6: <nil> Routes: [10.0.0.0/24 via 10.0.0.1 metric 5]"
	if got != want {
		t.Errorf("Interface.String()\n got %q\nwant %q", got, want)
	}
}

func TestFindInterfaceByName(t *testing.T) {
	eth0 := &Interface{Name: "eth0", Gateway4: net.ParseIP("203.0.113.1")}
	eth1 := &Interface{Name: "eth1"}
	pub6 := &Interface{Name: "eth2", Gateway6: net.ParseIP("2001:db8::1")}
	ifaces := []*Interface{eth1, eth0, pub6}

	t.Run("by name", func(t *testing.T) {
		if got := FindInterfaceByName("eth1", ifaces); got != eth1 {
			t.Errorf("got %v, want eth1", got)
		}
	})

	t.Run("public picks gateway4 interface", func(t *testing.T) {
		if got := FindInterfaceByName(Public, ifaces); got != eth0 {
			t.Errorf("got %v, want eth0", got)
		}
	})

	t.Run("public6 picks gateway6 interface", func(t *testing.T) {
		if got := FindInterfaceByName(Public6, ifaces); got != pub6 {
			t.Errorf("got %v, want pub6", got)
		}
	})

	t.Run("not found", func(t *testing.T) {
		if got := FindInterfaceByName("missing", ifaces); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("public with no gateway returns nil", func(t *testing.T) {
		if got := FindInterfaceByName(Public, []*Interface{eth1}); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("public6 with no gateway returns nil", func(t *testing.T) {
		if got := FindInterfaceByName(Public6, []*Interface{eth1}); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}

func TestReorderPrimaryAddress(t *testing.T) {
	// addrStrings renders a list of addresses for stable comparison.
	addrStrings := func(addrs []*net.IPNet) []string {
		out := make([]string, len(addrs))
		for i, a := range addrs {
			out[i] = a.IP.String()
		}
		return out
	}
	equal := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// hostIP keeps the host bits so IP.Equal matching is exercised, unlike the
	// network address returned by mustCIDR.
	hostIP := func(ip, cidr string) *net.IPNet {
		n := mustCIDR(t, cidr)
		return &net.IPNet{IP: net.ParseIP(ip), Mask: n.Mask}
	}

	a := hostIP("192.168.1.10", "192.168.1.10/24")
	b := hostIP("192.168.1.11", "192.168.1.11/24")
	c := hostIP("192.168.1.12", "192.168.1.12/24")
	v6 := hostIP("2001:db8::5", "2001:db8::5/64")

	t.Run("middle moves to front", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b, c}, b)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if want := []string{"192.168.1.11", "192.168.1.10", "192.168.1.12"}; !equal(addrStrings(got), want) {
			t.Errorf("got %v, want %v", addrStrings(got), want)
		}
	})

	t.Run("already first is unchanged", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b, c}, a)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}; !equal(addrStrings(got), want) {
			t.Errorf("got %v, want %v", addrStrings(got), want)
		}
	})

	t.Run("v6 target preserves v4 relative order", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b, v6}, v6)
		if !ok {
			t.Fatal("ok = false, want true")
		}
		if want := []string{"2001:db8::5", "192.168.1.10", "192.168.1.11"}; !equal(addrStrings(got), want) {
			t.Errorf("got %v, want %v", addrStrings(got), want)
		}
	})

	t.Run("absent target returns false", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b}, c)
		if ok {
			t.Error("ok = true, want false")
		}
		// The original slice is returned unchanged.
		if want := []string{"192.168.1.10", "192.168.1.11"}; !equal(addrStrings(got), want) {
			t.Errorf("got %v, want %v", addrStrings(got), want)
		}
	})
}

// fakeIfaceBackend records the calls made to it and optionally returns an error.
type fakeIfaceBackend struct {
	addrCalls  int
	routeCalls int
	dnsCalls   int
	lastAddrs  []*net.IPNet
	err        error
}

func (f *fakeIfaceBackend) SetIfaceAddresses(_ context.Context, iface string, addrs []*net.IPNet, gateway4, gateway6 net.IP) error {
	f.addrCalls++
	f.lastAddrs = addrs
	return f.err
}

func (f *fakeIfaceBackend) SetIfaceRoutes(_ context.Context, iface string, routes []*Route) error {
	f.routeCalls++
	return f.err
}

func (f *fakeIfaceBackend) SetIfaceDNS(_ context.Context, iface string, servers []net.IP, searchDomains []string) error {
	f.dnsCalls++
	return f.err
}

// fakePanelBackend records the calls made to it and optionally returns an error.
type fakePanelBackend struct {
	reloadCalls    int
	setMainIPCalls int
	removeIPCalls  int
	err            error
}

func (f *fakePanelBackend) reload(_ context.Context) error {
	f.reloadCalls++
	return f.err
}

func (f *fakePanelBackend) setMainIP(_ context.Context, addr net.IP) error {
	f.setMainIPCalls++
	return f.err
}

func (f *fakePanelBackend) removeIP(_ context.Context, addr net.IP) error {
	f.removeIPCalls++
	return f.err
}

// Every registered backend must be invoked even when an earlier backend
// returns an error, since each writes an independent configuration.
func TestApplyIfaceAddresses(t *testing.T) {
	failing := &fakeIfaceBackend{err: errors.New("boom")}
	ok := &fakeIfaceBackend{}
	backends := []namedIfaceBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	applyIfaceAddresses(context.Background(), backends, "eth0", nil, nil, nil)
	if failing.addrCalls != 1 || ok.addrCalls != 1 {
		t.Errorf("addr calls: failing=%d ok=%d, want 1 each", failing.addrCalls, ok.addrCalls)
	}
}

func TestApplyIfaceRoutes(t *testing.T) {
	failing := &fakeIfaceBackend{err: errors.New("boom")}
	ok := &fakeIfaceBackend{}
	backends := []namedIfaceBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	applyIfaceRoutes(context.Background(), backends, "eth0", nil)
	if failing.routeCalls != 1 || ok.routeCalls != 1 {
		t.Errorf("route calls: failing=%d ok=%d, want 1 each", failing.routeCalls, ok.routeCalls)
	}
}

func TestReloadPanels(t *testing.T) {
	failing := &fakePanelBackend{err: errors.New("boom")}
	ok := &fakePanelBackend{}
	backends := []namedPanelBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	reloadPanels(context.Background(), backends)
	if failing.reloadCalls != 1 || ok.reloadCalls != 1 {
		t.Errorf("reload calls: failing=%d ok=%d, want 1 each", failing.reloadCalls, ok.reloadCalls)
	}
}

func TestSetMainIPOnPanels(t *testing.T) {
	failing := &fakePanelBackend{err: errors.New("boom")}
	ok := &fakePanelBackend{}
	backends := []namedPanelBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	setMainIPOnPanels(context.Background(), backends, net.ParseIP("192.0.2.5"))
	if failing.setMainIPCalls != 1 || ok.setMainIPCalls != 1 {
		t.Errorf("setMainIP calls: failing=%d ok=%d, want 1 each", failing.setMainIPCalls, ok.setMainIPCalls)
	}
}

func TestRemoveIPFromPanels(t *testing.T) {
	failing := &fakePanelBackend{err: errors.New("boom")}
	ok := &fakePanelBackend{}
	backends := []namedPanelBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	removeIPFromPanels(context.Background(), backends, net.ParseIP("192.0.2.5"))
	if failing.removeIPCalls != 1 || ok.removeIPCalls != 1 {
		t.Errorf("removeIP calls: failing=%d ok=%d, want 1 each", failing.removeIPCalls, ok.removeIPCalls)
	}
}

// fakeDNSReaderBackend is a file backend that also reports back persisted
// interfaces (including DNS), satisfying both ifaceBackend and ifaceDNSReader.
type fakeDNSReaderBackend struct {
	ifaces []*Interface
	err    error
}

func (f *fakeDNSReaderBackend) SetIfaceAddresses(context.Context, string, []*net.IPNet, net.IP, net.IP) error {
	return nil
}
func (f *fakeDNSReaderBackend) SetIfaceRoutes(context.Context, string, []*Route) error { return nil }
func (f *fakeDNSReaderBackend) SetIfaceDNS(context.Context, string, []net.IP, []string) error {
	return nil
}
func (f *fakeDNSReaderBackend) GetInterfaces() ([]*Interface, error) { return f.ifaces, f.err }

// mergeDNSFromBackends must union DNS from every backend into the matching
// runtime interface (by name), de-duplicate entries so multi-backend hosts do
// not list a resolver twice, skip backends with no matching interface, and keep
// going when one backend errors.
func TestMergeDNSFromBackends(t *testing.T) {
	runtime := []*Interface{{Name: "eth0"}, {Name: "eth1"}}
	backends := []namedIfaceBackend{
		{name: "broken", backend: &fakeDNSReaderBackend{err: errors.New("boom")}},
		{name: "netplan", backend: &fakeDNSReaderBackend{ifaces: []*Interface{
			{Name: "eth0", DNS: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888")}, SearchDomains: []string{"example.com"}},
		}}},
		{name: "cloud-init", backend: &fakeDNSReaderBackend{ifaces: []*Interface{
			// Overlaps netplan (must dedupe) and adds one new entry.
			{Name: "eth0", DNS: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}, SearchDomains: []string{"example.com", "corp.example"}},
		}}},
		{name: "ifupdown", backend: &fakeDNSReaderBackend{ifaces: []*Interface{
			{Name: "eth1", DNS: []net.IP{net.ParseIP("9.9.9.9")}, SearchDomains: []string{"a.test"}},
			// No runtime match; must be ignored.
			{Name: "eth9", DNS: []net.IP{net.ParseIP("10.0.0.1")}},
		}}},
	}
	mergeDNSFromBackends(backends, runtime)

	eth0 := runtime[0]
	wantDNS := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888"), net.ParseIP("1.1.1.1")}
	if !equalIPs(eth0.DNS, wantDNS) {
		t.Errorf("eth0 DNS = %v, want %v", eth0.DNS, wantDNS)
	}
	wantSearch := []string{"example.com", "corp.example"}
	if len(eth0.SearchDomains) != len(wantSearch) || eth0.SearchDomains[0] != wantSearch[0] || eth0.SearchDomains[1] != wantSearch[1] {
		t.Errorf("eth0 SearchDomains = %v, want %v", eth0.SearchDomains, wantSearch)
	}

	eth1 := runtime[1]
	if !equalIPs(eth1.DNS, []net.IP{net.ParseIP("9.9.9.9")}) {
		t.Errorf("eth1 DNS = %v, want [9.9.9.9]", eth1.DNS)
	}
	if len(eth1.SearchDomains) != 1 || eth1.SearchDomains[0] != "a.test" {
		t.Errorf("eth1 SearchDomains = %v, want [a.test]", eth1.SearchDomains)
	}
}

func equalIPs(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
