package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
	if err != nil {
		t.Fatal("Failed to create new netns", err)
	}

	link, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("Failed to find \"lo\" in new netns: %v", err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		t.Fatalf("Failed to bring up \"lo\" in new netns: %v", err)
	}

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
	if err != nil {
		t.Fatalf("AddrList: %v", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Setup test link.
	name := "test_enp1s0"
	link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         name,
		HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x8b, 0x0d, 0x93},
	}})
	if err = h.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	if err = h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	// Add two addresses in the same subnet. The first added is the primary.
	primaryIP := &net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(24, 32)}
	secondaryIP := &net.IPNet{IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(24, 32)}
	if err = h.AddrAdd(link, &netlink.Addr{IPNet: primaryIP}); err != nil {
		t.Fatal(err)
	}
	if err = h.AddrAdd(link, &netlink.Addr{IPNet: secondaryIP}); err != nil {
		t.Fatal(err)
	}

	// Add a default route via the subnet so connectivity verification has a
	// gateway to work with.
	gw := net.ParseIP("1.2.3.1")
	if err = h.RouteAdd(&netlink.Route{
		Family:    netlink.FAMILY_V4,
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Gw:        gw,
	}); err != nil {
		t.Fatal(err)
	}

	// Sanity check the initial primary/secondary assignment.
	if _, primary := isPrimary(t, h, link, primaryIP.IP); !primary {
		t.Fatal("expected 1.2.3.4 to start as primary")
	}
	if _, primary := isPrimary(t, h, link, secondaryIP.IP); primary {
		t.Fatal("expected 1.2.3.5 to start as secondary")
	}

	// Configurator with the success sentinel and a capturing backend.
	backend := &fakeIfaceBackend{}
	c := &linuxConfigurator{configOptions: &configOptions{testAddress: "test_success"}}
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"fake", backend})

	// Promote the secondary to primary.
	if err = c.SetPrimaryAddress(context.Background(), name, secondaryIP); err != nil {
		t.Fatalf("SetPrimaryAddress: %v", err)
	}

	// The kernel should now treat 1.2.3.5 as primary and 1.2.3.4 as secondary,
	// with both addresses still present and the default route intact.
	if present, primary := isPrimary(t, h, link, secondaryIP.IP); !present || !primary {
		t.Errorf("after promotion 1.2.3.5: present=%v primary=%v, want both true", present, primary)
	}
	if present, primary := isPrimary(t, h, link, primaryIP.IP); !present || primary {
		t.Errorf("after promotion 1.2.3.4: present=%v primary=%v, want present true primary false", present, primary)
	}
	routes, err := h.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatal(err)
	}
	haveDefault := false
	for _, r := range routes {
		if ones, _ := r.Dst.Mask.Size(); ones == 0 && r.Gw.Equal(gw) {
			haveDefault = true
		}
	}
	if !haveDefault {
		t.Error("default route missing after promotion")
	}

	// The persisted config must receive the reordered list, primary first.
	if len(backend.lastAddrs) == 0 || !backend.lastAddrs[0].IP.Equal(secondaryIP.IP) {
		t.Errorf("backend primary = %v, want 1.2.3.5 first", backend.lastAddrs)
	}

	// Promoting the already-primary address is a no-op that still succeeds.
	if err = c.SetPrimaryAddress(context.Background(), name, secondaryIP); err != nil {
		t.Errorf("SetPrimaryAddress (idempotent): %v", err)
	}
	if _, primary := isPrimary(t, h, link, secondaryIP.IP); !primary {
		t.Error("1.2.3.5 should remain primary after idempotent call")
	}

	// Promoting an address not on the interface must error before any change.
	absent := &net.IPNet{IP: net.ParseIP("1.2.3.99"), Mask: net.CIDRMask(24, 32)}
	err = c.SetPrimaryAddress(context.Background(), name, absent)
	if err == nil || err.Error() != "address not found on interface" {
		t.Errorf("absent address error = %v, want \"address not found on interface\"", err)
	}
}

// TestLinuxRemovePrimaryRefused verifies that RemoveAddress refuses to remove
// the primary address of its family by default, and that WithAllowPrimaryRemoval
// overrides the refusal.
func TestLinuxRemovePrimaryRefused(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	h, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	name := "test_enp1s0"
	link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	if err = h.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	if err = h.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}

	primaryIP := &net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(24, 32)}
	if err = h.AddrAdd(link, &netlink.Addr{IPNet: primaryIP}); err != nil {
		t.Fatal(err)
	}

	c := &linuxConfigurator{configOptions: &configOptions{testAddress: "test_success"}}
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"fake", &fakeIfaceBackend{}})

	// Default: removing the primary is refused.
	err = c.RemoveAddress(context.Background(), name, primaryIP)
	if err == nil || !contains(err.Error(), "refusing to remove primary address") {
		t.Errorf("RemoveAddress primary = %v, want refusal error", err)
	}

	// With the override enabled, removal succeeds.
	c.allowPrimaryRemoval = true
	if err = c.RemoveAddress(context.Background(), name, primaryIP); err != nil {
		t.Errorf("RemoveAddress with allowPrimaryRemoval: %v", err)
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestLinuxConfigurator(t *testing.T) {
	tearDown := setupNetlinkTest(t)
	defer tearDown()

	// Connect to netlink.
	h, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Setup test link.
	eth0Name := "test_enp1s0"
	eth0Link := netlink.Link(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         eth0Name,
		HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x8b, 0x0d, 0x93},
	}})
	err = h.LinkAdd(eth0Link)
	if err != nil {
		t.Fatal(err)
	}

	// Set test link up.
	err = h.LinkSetUp(eth0Link)
	if err != nil {
		t.Fatal(err)
	}

	// Add test IP.
	testIP1 := &net.IPNet{
		IP:   net.ParseIP("1.2.3.4"),
		Mask: net.CIDRMask(24, 32),
	}
	err = h.AddrAdd(eth0Link, &netlink.Addr{IPNet: testIP1})
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}

	// Setup test link.
	eth1Name := "test_enp2s0"
	eth1Link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         eth1Name,
		HardwareAddr: net.HardwareAddr{0x52, 0x54, 0x00, 0x8b, 0xad, 0x93},
	}}
	err = h.LinkAdd(eth1Link)
	if err != nil {
		t.Fatal(err)
	}

	// Set test link up.
	err = h.LinkSetUp(eth1Link)
	if err != nil {
		t.Fatal(err)
	}

	// Add test IP.
	testIP2 := &net.IPNet{
		IP:   net.ParseIP("fc00:5aa8:7160:d9eb:1:0:1:3"),
		Mask: net.CIDRMask(64, 128),
	}
	err = h.AddrAdd(eth1Link, &netlink.Addr{IPNet: testIP2})
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}

	// Setup configurator with test URL to test server.
	c := &linuxConfigurator{configOptions: &configOptions{}}
	c.testAddress = "test_success"
	// The test intentionally removes addresses that are primary at runtime;
	// enable the override so the removal calls succeed.
	c.allowPrimaryRemoval = true

	// Setup test results path.
	testDir, err := filepath.Abs("./tests/configurator_linux")
	if err != nil {
		t.Fatal(err)
	}
	resultsDir := filepath.Join(testDir, "results")
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tmpDir, "50-cloud-init.yaml")
	err = fileCopy(filepath.Join(testDir, "50-cloud-init.yaml"), configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Setup ifupdown and parse test file.
	ci, err := newCloudInitWith(configPath, filepath.Join(tmpDir, "nothing.json"), filepath.Join(tmpDir, "cloud.cfg.d"))
	if err != nil {
		t.Fatal(err)
	}
	c.ifaceBackends = append(c.ifaceBackends, namedIfaceBackend{"cloud-init", ci})

	// Get list of interfaces.
	interfaces, err := c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 1)
	if err != nil {
		t.Error(err)
	}

	// Test add addresses.
	testIP3 := &net.IPNet{IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(24, 32)}
	err = c.AddAddress(context.Background(), eth0Name, testIP3, nil)
	if err != nil {
		t.Error(err)
	}
	testIP4 := &net.IPNet{IP: net.ParseIP("fc00:5aa8:7160:d9eb:1:0:1:5"), Mask: net.CIDRMask(64, 128)}
	err = c.AddAddress(context.Background(), eth1Name, testIP4, net.ParseIP("fc00:5aa8:7160:d9eb::"))
	if err != nil {
		t.Error(err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 2)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 1)
	if err != nil {
		t.Error(err)
	}

	// Test remove addresses.
	err = c.RemoveAddress(context.Background(), eth0Name, testIP1)
	if err != nil {
		t.Error(err)
	}
	err = c.RemoveAddress(context.Background(), eth1Name, testIP2)
	if err != nil {
		t.Error(err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	if err != nil {
		t.Error(err)
	}

	// Test rollback on failures.
	c.testAddress = "test_fail"
	err = c.AddAddress(context.Background(), eth0Name, testIP1, nil)
	if err == nil || err.Error() != "aborted operation due to loss of internet" {
		t.Errorf("Failed rollback test: %v", err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	if err != nil {
		t.Error(err)
	}

	// Test remove gateway.
	err = c.AddAddress(context.Background(), eth0Name, testIP3, make(net.IP, 4))
	if err != nil {
		t.Error(err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 4)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 3)
	if err != nil {
		t.Error(err)
	}

	// Test add gateway rollback.
	err = c.AddAddress(context.Background(), eth0Name, testIP3, testGW1)
	if err == nil || err.Error() != "aborted operation due to loss of internet" {
		t.Errorf("Failed rollback test: %v", err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 4)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 3)
	if err != nil {
		t.Error(err)
	}

	// Test remove gateway.
	c.testAddress = "test_success"
	err = c.AddAddress(context.Background(), eth0Name, testIP3, testGW1)
	if err != nil {
		t.Error(err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	if err != nil {
		t.Error(err)
	}

	// Test removing route.
	err = c.RemoveRoute(context.Background(), eth1Name, ipv6Dest, testGW2)
	if err != nil {
		t.Error(err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 5)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 4)
	if err != nil {
		t.Error(err)
	}

	// Test add route.
	ipv4Dest := &net.IPNet{
		IP:   net.ParseIP("10.0.10.0"),
		Mask: net.CIDRMask(24, 32),
	}
	testGW3 := net.ParseIP("1.2.3.254")
	err = c.AddRoute(context.Background(), eth0Name, ipv4Dest, testGW3, 100)
	if err != nil {
		t.Error(err)
	}

	// Get list of interfaces.
	interfaces, err = c.GetInterfaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 6)
	if err != nil {
		t.Error(err)
	}

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 5)
	if err != nil {
		t.Error(err)
	}
}
