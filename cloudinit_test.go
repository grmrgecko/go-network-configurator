package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Validate the cloud-init configuration parser/writer functions.
func TestCloudinit(t *testing.T) {
	// Setup test file.
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tmpDir, "network.yaml")
	testDir, err := filepath.Abs("./tests/cloudinit")
	if err != nil {
		t.Fatal(err)
	}
	resultsDir := filepath.Join(testDir, "results")
	err = fileCopy(filepath.Join(testDir, "network.yaml"), configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Setup ifupdown and parse test file.
	ci, err := newCloudInitWith(configPath, filepath.Join(tmpDir, "nothing.json"), filepath.Join(tmpDir, "cloud.cfg.d"))
	if err != nil {
		t.Fatal(err)
	}

	// Get the interfaces state.
	interfaces, err := ci.GetInterfaces()
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 1)
	if err != nil {
		t.Error(err)
	}

	// Test setting the IP addresses on an interface.
	err = ci.SetIfaceAddresses(context.Background(), "test_eth0.1556", []*net.IPNet{
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
	if err != nil {
		t.Fatal(err)
	}

	// Test setting routes on an interface.
	err = ci.SetIfaceRoutes(context.Background(), "test_eth3", []*Route{
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
	if err != nil {
		t.Fatal(err)
	}

	// Get the interfaces state.
	interfaces, err = ci.GetInterfaces()
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

	// Test setting the IP addresses on an interface.
	err = ci.SetIfaceAddresses(context.Background(), "test_eth0", []*net.IPNet{
		{
			IP:   net.ParseIP("1.2.10.4"),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.ParseIP("1.2.10.254"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Test setting routes on an interface.
	err = ci.SetIfaceRoutes(context.Background(), "test_eth0.1556", []*Route{})
	if err != nil {
		t.Fatal(err)
	}

	// Get the interfaces state.
	interfaces, err = ci.GetInterfaces()
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

	// Cleanup.
	err = os.RemoveAll(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
}

// Validate the cloudbase-init configuration parser/writer functions.
func TestCloudbaseinit(t *testing.T) {
	// Setup test file.
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(tmpDir, "network.json")
	testDir, err := filepath.Abs("./tests/cloudinit/cloudbase")
	if err != nil {
		t.Fatal(err)
	}
	resultsDir := filepath.Join(testDir, "results")
	err = fileCopy(filepath.Join(testDir, "network.json"), configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Setup ifupdown and parse test file.
	ci, err := newCloudInitWith(filepath.Join(tmpDir, "nothing.yaml"), configPath, filepath.Join(tmpDir, "cloud.cfg.d"))
	if err != nil {
		t.Fatal(err)
	}

	// Get the interfaces state.
	interfaces, err := ci.GetInterfaces()
	if err != nil {
		t.Fatal(err)
	}

	// Verify interfaces read from file.
	err = testVerifyInterfaces(interfaces, resultsDir, 1)
	if err != nil {
		t.Error(err)
	}

	// Test setting the IP addresses on an interface.
	err = ci.SetIfaceAddresses(context.Background(), "test_eth0.1556", []*net.IPNet{
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
	if err != nil {
		t.Fatal(err)
	}

	// Test setting routes on an interface.
	err = ci.SetIfaceRoutes(context.Background(), "test_eth3", []*Route{
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
	if err != nil {
		t.Fatal(err)
	}

	// Get the interfaces state.
	interfaces, err = ci.GetInterfaces()
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

	// Test setting the IP addresses on an interface.
	err = ci.SetIfaceAddresses(context.Background(), "test_eth0", []*net.IPNet{
		{
			IP:   net.ParseIP("1.2.10.4"),
			Mask: net.CIDRMask(24, 32),
		},
	}, net.ParseIP("1.2.10.254"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Test setting routes on an interface.
	err = ci.SetIfaceRoutes(context.Background(), "test_eth0.1556", []*Route{})
	if err != nil {
		t.Fatal(err)
	}

	// Get the interfaces state.
	interfaces, err = ci.GetInterfaces()
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

	// Cleanup.
	err = os.RemoveAll(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
}
