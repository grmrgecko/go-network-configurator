package netconfig

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	require.NoError(t, err)
	return n
}

func TestRouteString(t *testing.T) {
	r := &Route{
		Destination: mustCIDR(t, "10.0.0.0/24"),
		Gateway:     net.ParseIP("10.0.0.1"),
		Metric:      100,
	}
	assert.Equal(t, "10.0.0.0/24 via 10.0.0.1 metric 100", r.String())
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
	want := "Name: eth0 MAC: 00:11:22:33:44:55 Addresses: [192.168.1.0/24] Gateway4: 192.168.1.1 Gateway6: <nil> Routes: [10.0.0.0/24 via 10.0.0.1 metric 5]"
	assert.Equal(t, want, iface.String())
}

func TestFindInterfaceByName(t *testing.T) {
	eth0 := &Interface{Name: "eth0", Gateway4: net.ParseIP("203.0.113.1")}
	eth1 := &Interface{Name: "eth1"}
	pub6 := &Interface{Name: "eth2", Gateway6: net.ParseIP("2001:db8::1")}
	ifaces := []*Interface{eth1, eth0, pub6}

	t.Run("by name", func(t *testing.T) {
		assert.Equal(t, eth1, FindInterfaceByName("eth1", ifaces))
	})

	t.Run("public picks gateway4 interface", func(t *testing.T) {
		assert.Equal(t, eth0, FindInterfaceByName(Public, ifaces))
	})

	t.Run("public6 picks gateway6 interface", func(t *testing.T) {
		assert.Equal(t, pub6, FindInterfaceByName(Public6, ifaces))
	})

	t.Run("not found", func(t *testing.T) {
		assert.Nil(t, FindInterfaceByName("missing", ifaces))
	})

	t.Run("public with no gateway returns nil", func(t *testing.T) {
		assert.Nil(t, FindInterfaceByName(Public, []*Interface{eth1}))
	})

	t.Run("public6 with no gateway returns nil", func(t *testing.T) {
		assert.Nil(t, FindInterfaceByName(Public6, []*Interface{eth1}))
	})
}

// names extracts the interface names of a result slice, for comparing an
// expected ordering in one assertion.
func names(ifaces []*Interface) []string {
	out := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		out = append(out, iface.Name)
	}
	return out
}

func TestFindPhysicalInterfaces(t *testing.T) {
	t.Run("drops virtual interfaces", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "docker0", Up: true},
			{Name: "eth0", Up: true, Physical: true},
			{Name: "veth1a2b", Up: true},
		}
		assert.Equal(t, []string{"eth0"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("up before down", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "eth0", Physical: true},
			{Name: "eth1", Up: true, Physical: true},
		}
		assert.Equal(t, []string{"eth1", "eth0"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("gateway before none, v4 before v6", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "eth0", Up: true, Physical: true},
			{Name: "eth1", Up: true, Physical: true, Gateway6: net.ParseIP("2001:db8::1")},
			{Name: "eth2", Up: true, Physical: true, Gateway4: net.ParseIP("203.0.113.1")},
		}
		assert.Equal(t, []string{"eth2", "eth1", "eth0"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("up outranks a gateway on a down interface", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "eth0", Physical: true, Gateway4: net.ParseIP("203.0.113.1")},
			{Name: "eth1", Up: true, Physical: true},
		}
		assert.Equal(t, []string{"eth1", "eth0"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("wired before wireless before other", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "ppp0", Up: true, Physical: true},
			{Name: "wlp2s0", Up: true, Physical: true},
			{Name: "enp1s0", Up: true, Physical: true},
		}
		assert.Equal(t, []string{"enp1s0", "wlp2s0", "ppp0"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("names ordered as a human reads them", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "eth10", Up: true, Physical: true},
			{Name: "eth2", Up: true, Physical: true},
			{Name: "eth0", Up: true, Physical: true},
		}
		assert.Equal(t, []string{"eth0", "eth2", "eth10"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("windows friendly names rank as wired and wireless", func(t *testing.T) {
		ifaces := []*Interface{
			{Name: "Wi-Fi", Up: true, Physical: true},
			{Name: "Ethernet 2", Up: true, Physical: true},
		}
		assert.Equal(t, []string{"Ethernet 2", "Wi-Fi"}, names(FindPhysicalInterfaces(ifaces)))
	})

	t.Run("no physical interfaces returns empty", func(t *testing.T) {
		assert.Empty(t, FindPhysicalInterfaces([]*Interface{{Name: "br0", Up: true}}))
		assert.Empty(t, FindPhysicalInterfaces(nil))
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
		require.True(t, ok)
		assert.Equal(t, []string{"192.168.1.11", "192.168.1.10", "192.168.1.12"}, addrStrings(got))
	})

	t.Run("already first is unchanged", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b, c}, a)
		require.True(t, ok)
		assert.Equal(t, []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}, addrStrings(got))
	})

	t.Run("v6 target preserves v4 relative order", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b, v6}, v6)
		require.True(t, ok)
		assert.Equal(t, []string{"2001:db8::5", "192.168.1.10", "192.168.1.11"}, addrStrings(got))
	})

	t.Run("absent target returns false", func(t *testing.T) {
		got, ok := reorderPrimaryAddress([]*net.IPNet{a, b}, c)
		assert.False(t, ok)
		// The original slice is returned unchanged.
		assert.Equal(t, []string{"192.168.1.10", "192.168.1.11"}, addrStrings(got))
	})
}

// fakeIfaceBackend records the calls made to it and optionally returns an error.
type fakeIfaceBackend struct {
	addrCalls  int
	routeCalls int
	dnsCalls   int
	dhcpCalls  int
	lastAddrs  []*net.IPNet
	lastDHCP4  bool
	lastDHCP6  bool
	err        error
}

func (f *fakeIfaceBackend) SetIfaceDHCP(_ context.Context, iface string, dhcp4, dhcp6 bool) error {
	f.dhcpCalls++
	f.lastDHCP4, f.lastDHCP6 = dhcp4, dhcp6
	return f.err
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
	assert.Equal(t, 1, failing.addrCalls)
	assert.Equal(t, 1, ok.addrCalls)
}

func TestApplyIfaceRoutes(t *testing.T) {
	failing := &fakeIfaceBackend{err: errors.New("boom")}
	ok := &fakeIfaceBackend{}
	backends := []namedIfaceBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	applyIfaceRoutes(context.Background(), backends, "eth0", nil)
	assert.Equal(t, 1, failing.routeCalls)
	assert.Equal(t, 1, ok.routeCalls)
}

func TestReloadPanels(t *testing.T) {
	failing := &fakePanelBackend{err: errors.New("boom")}
	ok := &fakePanelBackend{}
	backends := []namedPanelBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	reloadPanels(context.Background(), backends)
	assert.Equal(t, 1, failing.reloadCalls)
	assert.Equal(t, 1, ok.reloadCalls)
}

func TestSetMainIPOnPanels(t *testing.T) {
	failing := &fakePanelBackend{err: errors.New("boom")}
	ok := &fakePanelBackend{}
	backends := []namedPanelBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	setMainIPOnPanels(context.Background(), backends, net.ParseIP("192.0.2.5"))
	assert.Equal(t, 1, failing.setMainIPCalls)
	assert.Equal(t, 1, ok.setMainIPCalls)
}

func TestRemoveIPFromPanels(t *testing.T) {
	failing := &fakePanelBackend{err: errors.New("boom")}
	ok := &fakePanelBackend{}
	backends := []namedPanelBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	removeIPFromPanels(context.Background(), backends, net.ParseIP("192.0.2.5"))
	assert.Equal(t, 1, failing.removeIPCalls)
	assert.Equal(t, 1, ok.removeIPCalls)
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
func (f *fakeDNSReaderBackend) SetIfaceDHCP(context.Context, string, bool, bool) error { return nil }
func (f *fakeDNSReaderBackend) GetInterfaces() ([]*Interface, error)                   { return f.ifaces, f.err }

// mergeBackendState must union DNS from every backend into the matching runtime
// interface (by name), de-duplicate entries so multi-backend hosts do not list a
// resolver twice, OR the DHCP flags so a client enabled in any backend is
// reported, skip backends with no matching interface, and keep going when one
// backend errors.
func TestMergeBackendState(t *testing.T) {
	runtime := []*Interface{{Name: "eth0"}, {Name: "eth1"}}
	backends := []namedIfaceBackend{
		{name: "broken", backend: &fakeDNSReaderBackend{err: errors.New("boom")}},
		{name: "netplan", backend: &fakeDNSReaderBackend{ifaces: []*Interface{
			{Name: "eth0", DNS: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888")}, SearchDomains: []string{"example.com"}, DHCP4: true},
		}}},
		{name: "cloud-init", backend: &fakeDNSReaderBackend{ifaces: []*Interface{
			// Overlaps netplan (must dedupe) and adds one new entry. DHCP4 is
			// false here and must not clear the true netplan reported.
			{Name: "eth0", DNS: []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")}, SearchDomains: []string{"example.com", "corp.example"}, DHCP6: true},
		}}},
		{name: "ifupdown", backend: &fakeDNSReaderBackend{ifaces: []*Interface{
			{Name: "eth1", DNS: []net.IP{net.ParseIP("9.9.9.9")}, SearchDomains: []string{"a.test"}},
			// No runtime match; must be ignored.
			{Name: "eth9", DNS: []net.IP{net.ParseIP("10.0.0.1")}, DHCP4: true},
		}}},
	}
	mergeBackendState(backends, runtime)

	eth0 := runtime[0]
	wantDNS := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888"), net.ParseIP("1.1.1.1")}
	assert.True(t, equalIPs(eth0.DNS, wantDNS))
	wantSearch := []string{"example.com", "corp.example"}
	assert.Equal(t, wantSearch, eth0.SearchDomains)
	assert.True(t, eth0.DHCP4, "netplan reported DHCP4; cloud-init's false must not clear it")
	assert.True(t, eth0.DHCP6, "cloud-init reported DHCP6")

	eth1 := runtime[1]
	assert.True(t, equalIPs(eth1.DNS, []net.IP{net.ParseIP("9.9.9.9")}))
	assert.Equal(t, []string{"a.test"}, eth1.SearchDomains)
	assert.False(t, eth1.DHCP4, "eth9's DHCP4 must not leak onto eth1")
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
