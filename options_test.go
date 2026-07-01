package netconfig

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogger records the last formatted message so SetLogger can be
// verified.
type captureLogger struct {
	printfCalls  int
	printlnCalls int
}

func (c *captureLogger) Printf(format string, args ...interface{}) { c.printfCalls++ }
func (c *captureLogger) Println(args ...interface{})               { c.printlnCalls++ }

func TestConfigOptionsDefaults(t *testing.T) {
	o := newConfigOptions()
	assert.Equal(t, defaultInternetTestAddress, o.testAddress)
	assert.False(t, o.skipConnectivityCheck)
	assert.Equal(t, defaultConnectivityTimeout, o.connectivityTimeout)
	assert.Equal(t, defaultPingCount, o.pingCount)
	assert.Equal(t, defaultPingTimeout, o.pingTimeout)
	assert.Equal(t, defaultBackupRetention, o.backupRetention)
	assert.Equal(t, defaultServiceReadyTimeout, o.serviceReadyTimeout)
	assert.False(t, o.allowPrimaryRemoval)
	assert.False(t, o.skipPanels)
	assert.False(t, o.allowNoBackends)
}

func TestWithServiceReadyTimeout(t *testing.T) {
	o := newConfigOptions(WithServiceReadyTimeout(90 * time.Second))
	assert.Equal(t, 90*time.Second, o.serviceReadyTimeout)

	// Zero and negative both mean "do not wait", and must be preserved rather
	// than falling back to the default the way WithTestAddress("") does.
	o = newConfigOptions(WithServiceReadyTimeout(0))
	assert.Equal(t, time.Duration(0), o.serviceReadyTimeout)
	o = newConfigOptions(WithServiceReadyTimeout(-1))
	assert.Equal(t, -1*time.Nanosecond, o.serviceReadyTimeout)
}

func TestWithTestAddress(t *testing.T) {
	o := newConfigOptions(WithTestAddress("http://canary.example/health"))
	assert.Equal(t, "http://canary.example/health", o.testAddress)
	// An empty address must not clobber the default.
	o = newConfigOptions(WithTestAddress(""))
	assert.Equal(t, defaultInternetTestAddress, o.testAddress)
}

func TestWithConnectivityCheck(t *testing.T) {
	o := newConfigOptions(WithConnectivityCheck(false))
	assert.True(t, o.skipConnectivityCheck)
	o = newConfigOptions(WithConnectivityCheck(true))
	assert.False(t, o.skipConnectivityCheck)
}

func TestWithSkipConnectivityCheck(t *testing.T) {
	o := newConfigOptions(WithSkipConnectivityCheck())
	assert.True(t, o.skipConnectivityCheck)
}

func TestSetLogger(t *testing.T) {
	prev := logger
	defer func() { logger = prev }()

	cap := &captureLogger{}
	SetLogger(cap)
	require.Equal(t, cap, logger)
	logger.Printf("hi %d", 1)
	logger.Println("hi")
	assert.Equal(t, 1, cap.printfCalls)
	assert.Equal(t, 1, cap.printlnCalls)

	// A nil logger must be ignored, leaving the current logger in place.
	SetLogger(nil)
	assert.Equal(t, cap, logger)
}

func TestWithConnectivityTimeout(t *testing.T) {
	o := newConfigOptions(WithConnectivityTimeout(5 * time.Second))
	assert.Equal(t, 5*time.Second, o.connectivityTimeout)
	// Non-positive values must not clobber the default.
	o = newConfigOptions(WithConnectivityTimeout(0))
	assert.Equal(t, defaultConnectivityTimeout, o.connectivityTimeout)
}

func TestWithPingCount(t *testing.T) {
	o := newConfigOptions(WithPingCount(3))
	assert.Equal(t, 3, o.pingCount)
	// Non-positive values must not clobber the default.
	o = newConfigOptions(WithPingCount(0))
	assert.Equal(t, defaultPingCount, o.pingCount)
}

func TestWithPingTimeout(t *testing.T) {
	o := newConfigOptions(WithPingTimeout(30 * time.Second))
	assert.Equal(t, 30*time.Second, o.pingTimeout)
	o = newConfigOptions(WithPingTimeout(0))
	assert.Equal(t, defaultPingTimeout, o.pingTimeout)
}

func TestWithBackupRetention(t *testing.T) {
	o := newConfigOptions(WithBackupRetention(10))
	assert.Equal(t, 10, o.backupRetention)
	// Zero/negative disables pruning (keeps all backups).
	o = newConfigOptions(WithBackupRetention(0))
	assert.Equal(t, 0, o.backupRetention)
}

func TestWithAllowPrimaryRemoval(t *testing.T) {
	o := newConfigOptions(WithAllowPrimaryRemoval(true))
	assert.True(t, o.allowPrimaryRemoval)
}

func TestWithSkipPanels(t *testing.T) {
	o := newConfigOptions(WithSkipPanels(true))
	assert.True(t, o.skipPanels)
	o = newConfigOptions(WithSkipPanels(false))
	assert.False(t, o.skipPanels)
}

// applyIfaceDNS must invoke every backend even when an earlier one fails.
func TestApplyIfaceDNS(t *testing.T) {
	failing := &fakeIfaceBackend{err: errors.New("boom")}
	ok := &fakeIfaceBackend{}
	backends := []namedIfaceBackend{
		{name: "failing", backend: failing},
		{name: "ok", backend: ok},
	}
	applyIfaceDNS(context.Background(), backends, "eth0", []net.IP{net.ParseIP("8.8.8.8")}, []string{"example.com"})
	assert.Equal(t, 1, failing.dnsCalls)
	assert.Equal(t, 1, ok.dnsCalls)
}

func TestIPStrings(t *testing.T) {
	got := ipStrings([]net.IP{net.ParseIP("8.8.8.8"), nil, net.ParseIP("2001:4860:4860::8888")})
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	require.Equal(t, want, got)
}

// TestNetplanDNS round-trips DNS through the netplan backend: SetIfaceDNS writes
// the nameservers block and GetInterfaces parses it back.
func TestNetplanDNS(t *testing.T) {
	tmpDir := t.TempDir()
	config := "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [192.0.2.10/24]\n"
	err := os.WriteFile(filepath.Join(tmpDir, "01-test.yaml"), []byte(config), 0644)
	require.NoError(t, err)

	np, err := readNetplanConfigDirectory(tmpDir)
	require.NoError(t, err)

	servers := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888")}
	err = np.SetIfaceDNS(context.Background(), "eth0", servers, []string{"example.com", "corp.example"})
	require.NoError(t, err)

	// Re-read from disk so we exercise the written config, not in-memory state.
	np, err = readNetplanConfigDirectory(tmpDir)
	require.NoError(t, err)
	ifaces, err := np.GetInterfaces()
	require.NoError(t, err)

	var eth0 *Interface
	for _, i := range ifaces {
		if i.Name == "eth0" {
			eth0 = i
		}
	}
	require.NotNil(t, eth0)
	assert.True(t, len(eth0.DNS) == 2 && eth0.DNS[0].Equal(servers[0]) && eth0.DNS[1].Equal(servers[1]))
	assert.True(t, len(eth0.SearchDomains) == 2 && eth0.SearchDomains[0] == "example.com" && eth0.SearchDomains[1] == "corp.example")
}
