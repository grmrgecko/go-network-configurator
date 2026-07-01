package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Validate the network scripts configuration parser/writer functions.
func TestNetworkScripts(t *testing.T) {
	// Setup test file.
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	testDir, err := filepath.Abs("./tests/networkScripts")
	require.NoError(t, err)
	resultsDir := filepath.Join(testDir, "results")

	// Try to read the test directory for files to copy to our temporary directory.
	entries, err := os.ReadDir(testDir)
	require.NoError(t, err)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "ifcfg-") && !strings.HasPrefix(entry.Name(), "route-") && !strings.HasPrefix(entry.Name(), "route6-") {
			continue
		}

		configPath := filepath.Join(testDir, entry.Name())
		tmpPath := filepath.Join(tmpDir, entry.Name())
		err = fileCopy(configPath, tmpPath)
		require.NoError(t, err)
	}

	// Setup ifupdown and parse test file.
	ns, err := newNetworkScriptsWithConfig(tmpDir)
	require.NoError(t, err)

	// Get the interfaces state.
	interfaces, err := ns.GetInterfaces()
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 1)
	require.NoError(t, err)

	// Test setting the IP addresses on an interface.
	err = ns.SetIfaceAddresses(context.Background(), "test_eth0.1556", []*net.IPNet{
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
	err = ns.SetIfaceRoutes(context.Background(), "test_eth2", []*Route{
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

	// Verify we can re-read configurations.
	ns, err = newNetworkScriptsWithConfig(tmpDir)
	require.NoError(t, err)

	// Get the interfaces state.
	interfaces, err = ns.GetInterfaces()
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 2)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 1)
	require.NoError(t, err)

	// Test setting the IP addresses on an interface.
	err = ns.SetIfaceAddresses(context.Background(), "test_eth0", []*net.IPNet{
		{
			IP:   net.ParseIP("1.2.10.4"),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.ParseIP("1.2.10.254"), nil)
	require.NoError(t, err)

	// Test setting routes on an interface.
	err = ns.SetIfaceRoutes(context.Background(), "test_eth0.1556", []*Route{})
	require.NoError(t, err)

	// Verify we can re-read configurations.
	ns, err = newNetworkScriptsWithConfig(tmpDir)
	require.NoError(t, err)

	// Get the interfaces state.
	interfaces, err = ns.GetInterfaces()
	require.NoError(t, err)

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 3)
	require.NoError(t, err)

	// Read the current file and expected state.
	err = testVerifyResults(resultsDir, tmpDir, 2)
	require.NoError(t, err)

	// Cleanup.
	err = os.RemoveAll(tmpDir)
	require.NoError(t, err)
}
