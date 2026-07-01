package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Function to setup a test namespace for test network interfaces.
func setupNetlinkTest(t testing.TB) func() {
	t.Helper()

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	runtime.LockOSThread()
	ns, err := netns.New()
	require.NoError(t, err, "Failed to create new netns")

	link, err := netlink.LinkByName("lo")
	require.NoError(t, err, "Failed to find \"lo\" in new netns")
	err = netlink.LinkSetUp(link)
	require.NoError(t, err, "Failed to bring up \"lo\" in new netns")

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

// isPrimary reports whether the given IP is currently the primary address of
// its subnet on the link, i.e. the kernel has not flagged it IFA_F_SECONDARY.
// It also confirms the address is present at all.
func isPrimary(t testing.TB, h *netlink.Handle, link netlink.Link, ip net.IP) (present, primary bool) {
	t.Helper()
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	require.NoError(t, err, "AddrList")
	for _, a := range addrs {
		if a.IPNet.IP.Equal(ip) {
			return true, a.Flags&unix.IFA_F_SECONDARY == 0
		}
	}
	return false, false
}

// TestLinuxSetPrimaryAddress exercises the netlink reordering performed by
// SetPrimaryAddress: promoting a secondary same-subnet address to primary,
// idempotency when already primary, and the error when the address is absent.
func TestLinuxSetPrimaryAddress(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	h, err := netlink.NewHandle()
	require.NoError(t, err)
	defer h.Close()

	// Setup test link.
	name := "test_enp1s0"
	link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         name,
		HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x8b, 0x0d, 0x93},
	}})
	require.NoError(t, h.LinkAdd(link))
	require.NoError(t, h.LinkSetUp(link))

	// Add two addresses in the same subnet. The first added is the primary.
	primaryIP := &net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(24, 32)}
	secondaryIP := &net.IPNet{IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(24, 32)}
	require.NoError(t, h.AddrAdd(link, &netlink.Addr{IPNet: primaryIP}))
	require.NoError(t, h.AddrAdd(link, &netlink.Addr{IPNet: secondaryIP}))

	// Add a default route via the subnet so connectivity verification has a
	// gateway to work with.
	gw := net.ParseIP("1.2.3.1")
	require.NoError(t, h.RouteAdd(&netlink.Route{
		Family:    netlink.FAMILY_V4,
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:        gw,
	}))

	// Sanity check the initial primary/secondary assignment.
	_, primary := isPrimary(t, h, link, primaryIP.IP)
	require.True(t, primary, "expected 1.2.3.4 to start as primary")
	_, primary = isPrimary(t, h, link, secondaryIP.IP)
	require.False(t, primary, "expected 1.2.3.5 to start as secondary")

	// Configurator with the success sentinel and a capturing backend.
	backend := &fakeIfaceBackend{}
	c := &linuxConfigurator{configOptions: &configOptions{testAddress: "test_success"}}
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"fake", backend})

	// Promote the secondary to primary.
	require.NoError(t, c.SetPrimaryAddress(context.Background(), name, secondaryIP), "SetPrimaryAddress")

	// The kernel should now treat 1.2.3.5 as primary and 1.2.3.4 as secondary,
	// with both addresses still present and the default route intact.
	present, primary := isPrimary(t, h, link, secondaryIP.IP)
	assert.True(t, present && primary, "after promotion 1.2.3.5: present=%v primary=%v, want both true", present, primary)
	present, primary = isPrimary(t, h, link, primaryIP.IP)
	assert.True(t, present && !primary, "after promotion 1.2.3.4: present=%v primary=%v, want present true primary false", present, primary)
	routes, err := h.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	haveDefault := false
	for _, r := range routes {
		if ones, _ := r.Dst.Mask.Size(); ones == 0 && r.Gw.Equal(gw) {
			haveDefault = true
		}
	}
	assert.True(t, haveDefault, "default route missing after promotion")

	// The persisted config must receive the reordered list, primary first.
	assert.True(t, len(backend.lastAddrs) != 0 && backend.lastAddrs[0].IP.Equal(secondaryIP.IP), "backend primary = %v, want 1.2.3.5 first", backend.lastAddrs)

	// Promoting the already-primary address is a no-op that still succeeds.
	assert.NoError(t, c.SetPrimaryAddress(context.Background(), name, secondaryIP), "SetPrimaryAddress (idempotent)")
	_, primary = isPrimary(t, h, link, secondaryIP.IP)
	assert.True(t, primary, "1.2.3.5 should remain primary after idempotent call")

	// Promoting an address not on the interface must error before any change.
	absent := &net.IPNet{IP: net.ParseIP("1.2.3.99"), Mask: net.CIDRMask(24, 32)}
	err = c.SetPrimaryAddress(context.Background(), name, absent)
	assert.EqualError(t, err, "address not found on interface")
}

// adminUp reports whether the named link is administratively up, re-reading it
// from the kernel rather than trusting a cached netlink.Link.
func adminUp(t testing.TB, h *netlink.Handle, name string) bool {
	t.Helper()
	link, err := h.LinkByName(name)
	require.NoError(t, err, "LinkByName")
	return link.Attrs().Flags&net.FlagUp != 0
}

// hasDefaultRoute reports whether the link carries a default route via gw.
func hasDefaultRoute(t testing.TB, h *netlink.Handle, link netlink.Link, gw net.IP) bool {
	t.Helper()
	routes, err := h.RouteList(link, netlink.FAMILY_V4)
	require.NoError(t, err, "RouteList")
	for _, r := range routes {
		if ones, _ := r.Dst.Mask.Size(); ones == 0 && r.Gw.Equal(gw) {
			return true
		}
	}
	return false
}

// newDownLink creates a dummy link and deliberately leaves it administratively
// down, the starting state for the AddAddress tests below.
func newDownLink(t testing.TB, h *netlink.Handle, name string) netlink.Link {
	t.Helper()
	link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	require.NoError(t, h.LinkAdd(link), "LinkAdd")
	require.False(t, adminUp(t, h, name), "%s should start down", name)
	return link
}

// newPingerConfigurator builds a configurator whose ping settings are short
// enough that the unanswerable probes against a dummy link do not stall the
// test for the twenty second default.
func newPingerConfigurator(testAddress string) *linuxConfigurator {
	c := &linuxConfigurator{configOptions: &configOptions{
		testAddress: testAddress,
		pingCount:   1,
		pingTimeout: 100 * time.Millisecond,
	}}
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"fake", &fakeIfaceBackend{}})
	return c
}

// TestLinuxAddAddressBringsLinkUp covers AddAddress against an administratively
// down interface. The kernel installs no connected route for an address on a
// down link, so the default route would be rejected as unreachable unless the
// link is raised first.
func TestLinuxAddAddressBringsLinkUp(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	h, err := netlink.NewHandle()
	require.NoError(t, err)
	defer h.Close()

	name := "test_enp1s0"
	link := newDownLink(t, h, name)
	addr := &net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(24, 32)}
	gw := net.ParseIP("1.2.3.1")

	require.NoError(t, newPingerConfigurator("test_success").AddAddress(context.Background(), name, addr, gw), "AddAddress")
	assert.True(t, adminUp(t, h, name), "interface should be up after AddAddress")
	assert.True(t, hasDefaultRoute(t, h, link, gw), "default route via %s missing", gw)
	present, _ := isPrimary(t, h, link, addr.IP)
	assert.True(t, present, "address missing after AddAddress")
}

// TestLinuxAddAddressRestoresDownLink verifies that a link AddAddress raised is
// part of the pre-change state it restores: when the connectivity check fails,
// the interface goes back down along with the address and route rolled back.
// Its own namespace keeps the default route it adds from colliding with the one
// TestLinuxAddAddressBringsLinkUp installs, which the kernel refuses as EEXIST.
func TestLinuxAddAddressRestoresDownLink(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	h, err := netlink.NewHandle()
	require.NoError(t, err)
	defer h.Close()

	name := "test_enp1s0"
	link := newDownLink(t, h, name)
	addr := &net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(24, 32)}
	gw := net.ParseIP("1.2.3.1")

	err = newPingerConfigurator("test_fail").AddAddress(context.Background(), name, addr, gw)
	assert.EqualError(t, err, "aborted operation due to loss of internet")
	assert.False(t, adminUp(t, h, name), "interface should be down again after rollback")
	assert.False(t, hasDefaultRoute(t, h, link, gw), "default route should be rolled back")
	present, _ := isPrimary(t, h, link, addr.IP)
	assert.False(t, present, "address should be rolled back")
}

// TestLinuxRemovePrimaryRefused verifies that RemoveAddress refuses to remove
// the primary address of its family by default, and that WithAllowPrimaryRemoval
// overrides the refusal.
func TestLinuxRemovePrimaryRefused(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	h, err := netlink.NewHandle()
	require.NoError(t, err)
	defer h.Close()

	name := "test_enp1s0"
	link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	require.NoError(t, h.LinkAdd(link))
	require.NoError(t, h.LinkSetUp(link))

	primaryIP := &net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(24, 32)}
	require.NoError(t, h.AddrAdd(link, &netlink.Addr{IPNet: primaryIP}))

	c := &linuxConfigurator{configOptions: &configOptions{testAddress: "test_success"}}
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"fake", &fakeIfaceBackend{}})

	// Default: removing the primary is refused.
	err = c.RemoveAddress(context.Background(), name, primaryIP)
	assert.ErrorContains(t, err, "refusing to remove primary address")

	// With the override enabled, removal succeeds.
	c.allowPrimaryRemoval = true
	assert.NoError(t, c.RemoveAddress(context.Background(), name, primaryIP), "RemoveAddress with allowPrimaryRemoval")
}

func TestLinuxConfigurator(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	// Connect to netlink.
	h, err := netlink.NewHandle()
	require.NoError(t, err)
	defer h.Close()

	// Setup test link.
	eth0Name := "test_enp1s0"
	eth0Link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         eth0Name,
		HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x8b, 0x0d, 0x93},
	}})
	err = h.LinkAdd(eth0Link)
	require.NoError(t, err)

	// Set test link up.
	err = h.LinkSetUp(eth0Link)
	require.NoError(t, err)

	// Add test IP.
	testIP1 := &net.IPNet{
		IP:   net.ParseIP("1.2.3.4"),
		Mask: net.CIDRMask(24, 32),
	}
	err = h.AddrAdd(eth0Link, &netlink.Addr{IPNet: testIP1})
	require.NoError(t, err)

	// Add default route.
	testGW1 := net.ParseIP("1.2.3.1")
	defaultRoute := &netlink.Route{
		Family:    netlink.FAMILY_V4,
		LinkIndex: eth0Link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		Gw: testGW1,
	}
	err = h.RouteAdd(defaultRoute)
	require.NoError(t, err)

	// Setup test link.
	eth1Name := "test_enp2s0"
	eth1Link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         eth1Name,
		HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x8b, 0xad, 0x93},
	}}
	err = h.LinkAdd(eth1Link)
	require.NoError(t, err)

	// Set test link up.
	err = h.LinkSetUp(eth1Link)
	require.NoError(t, err)

	// Add test IP.
	testIP2 := &net.IPNet{
		IP:   net.ParseIP("fc00:5aa8:7160:d9eb:1:0:1:3"),
		Mask: net.CIDRMask(64, 128),
	}
	err = h.AddrAdd(eth1Link, &netlink.Addr{IPNet: testIP2})
	require.NoError(t, err)

	// Add default route.
	testGW2 := net.ParseIP("fe80::1")
	ipv6Dest := &net.IPNet{
		IP:   net.ParseIP("fc00:5aa8:7160:d9eb::1"),
		Mask: net.CIDRMask(128, 128),
	}
	ipv6Route := &netlink.Route{
		Family:    netlink.FAMILY_V6,
		LinkIndex: eth1Link.Attrs().Index,
		Dst:       ipv6Dest,
		Gw:        testGW2,
		Priority:  200,
	}
	err = h.RouteAdd(ipv6Route)
	require.NoError(t, err)

	// Setup configurator with test URL to test server.
	c := &linuxConfigurator{configOptions: &configOptions{}}
	c.testAddress = "test_success"
	// The test intentionally removes addresses that are primary at runtime;
	// enable the override so the removal calls succeed.
	c.allowPrimaryRemoval = true

	// Setup test results path.
	testDir, err := filepath.Abs("./tests/configurator_linux")
	require.NoError(t, err)
	resultsDir := filepath.Join(testDir, "results")
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	configPath := filepath.Join(tmpDir, "50-cloud-init.yaml")
	err = fileCopy(filepath.Join(testDir, "50-cloud-init.yaml"), configPath)
	require.NoError(t, err)

	// Setup ifupdown and parse test file.
	ci, err := newCloudInitWith(configPath, filepath.Join(tmpDir, "nothing.json"), filepath.Join(tmpDir, "cloud.cfg.d"))
	require.NoError(t, err)
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"cloud-init", ci})

	// Get list of interfaces.
	interfaces, err := c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 1)
	require.NoError(t, err)

	// Test add addresses.
	testIP3 := &net.IPNet{IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(24, 32)}
	err = c.AddAddress(context.Background(), eth0Name, testIP3, nil)
	assert.NoError(t, err)
	testIP4 := &net.IPNet{IP: net.ParseIP("fc00:5aa8:7160:d9eb:1:0:1:5"), Mask: net.CIDRMask(64, 128)}
	err = c.AddAddress(context.Background(), eth1Name, testIP4, net.ParseIP("fc00:5aa8:7160:d9eb::"))
	assert.NoError(t, err)

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 2)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 1)
	require.NoError(t, err)

	// Test remove addresses.
	err = c.RemoveAddress(context.Background(), eth0Name, testIP1)
	assert.NoError(t, err)
	err = c.RemoveAddress(context.Background(), eth1Name, testIP2)
	assert.NoError(t, err)

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	require.NoError(t, err)

	// Test rollback on failures.
	c.testAddress = "test_fail"
	err = c.AddAddress(context.Background(), eth0Name, testIP1, nil)
	assert.EqualError(t, err, "aborted operation due to loss of internet", "Failed rollback test")

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	require.NoError(t, err)

	// Test remove gateway.
	err = c.AddAddress(context.Background(), eth0Name, testIP3, make(net.IP, 4))
	assert.NoError(t, err)

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 4)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 3)
	require.NoError(t, err)

	// Test add gateway rollback.
	err = c.AddAddress(context.Background(), eth0Name, testIP3, testGW1)
	assert.EqualError(t, err, "aborted operation due to loss of internet", "Failed rollback test")

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 4)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 3)
	require.NoError(t, err)

	// Test remove gateway.
	c.testAddress = "test_success"
	err = c.AddAddress(context.Background(), eth0Name, testIP3, testGW1)
	assert.NoError(t, err)

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	require.NoError(t, err)

	// Test removing route.
	err = c.RemoveRoute(context.Background(), eth1Name, ipv6Dest, testGW2)
	assert.NoError(t, err)

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 5)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 4)
	require.NoError(t, err)

	// Test add route.
	ipv4Dest := &net.IPNet{
		IP:   net.ParseIP("10.0.10.0"),
		Mask: net.CIDRMask(24, 32),
	}
	testGW3 := net.ParseIP("1.2.3.254")
	err = c.AddRoute(context.Background(), eth0Name, ipv4Dest, testGW3, 100)
	assert.NoError(t, err)

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 6)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 5)
	require.NoError(t, err)
}
