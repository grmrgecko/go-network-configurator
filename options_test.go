package netconfig

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if o.testAddress != defaultInternetTestAddress {
		t.Errorf("default testAddress = %q, want %q", o.testAddress, defaultInternetTestAddress)
	}
	if o.skipConnectivityCheck {
		t.Error("skipConnectivityCheck = true, want false by default")
	}
	if o.connectivityTimeout != defaultConnectivityTimeout {
		t.Errorf("default connectivityTimeout = %v, want %v", o.connectivityTimeout, defaultConnectivityTimeout)
	}
	if o.pingCount != defaultPingCount {
		t.Errorf("default pingCount = %d, want %d", o.pingCount, defaultPingCount)
	}
	if o.pingTimeout != defaultPingTimeout {
		t.Errorf("default pingTimeout = %v, want %v", o.pingTimeout, defaultPingTimeout)
	}
	if o.backupRetention != defaultBackupRetention {
		t.Errorf("default backupRetention = %d, want %d", o.backupRetention, defaultBackupRetention)
	}
	if o.allowPrimaryRemoval {
		t.Error("allowPrimaryRemoval = true, want false by default")
	}
	if o.skipPanels {
		t.Error("skipPanels = true, want false by default")
	}
}

func TestWithTestAddress(t *testing.T) {
	o := newConfigOptions(WithTestAddress("http://canary.example/health"))
	if o.testAddress != "http://canary.example/health" {
		t.Errorf("testAddress = %q, want the overridden value", o.testAddress)
	}
	// An empty address must not clobber the default.
	o = newConfigOptions(WithTestAddress(""))
	if o.testAddress != defaultInternetTestAddress {
		t.Errorf("empty WithTestAddress changed default to %q", o.testAddress)
	}
}

func TestWithConnectivityCheck(t *testing.T) {
	if o := newConfigOptions(WithConnectivityCheck(false)); !o.skipConnectivityCheck {
		t.Error("WithConnectivityCheck(false) did not set skipConnectivityCheck")
	}
	if o := newConfigOptions(WithConnectivityCheck(true)); o.skipConnectivityCheck {
		t.Error("WithConnectivityCheck(true) set skipConnectivityCheck")
	}
}

func TestWithSkipConnectivityCheck(t *testing.T) {
	if o := newConfigOptions(WithSkipConnectivityCheck()); !o.skipConnectivityCheck {
		t.Error("WithSkipConnectivityCheck did not set skipConnectivityCheck")
	}
}

func TestSetLogger(t *testing.T) {
	prev := logger
	defer func() { logger = prev }()

	cap := &captureLogger{}
	SetLogger(cap)
	if logger != cap {
		t.Fatal("SetLogger did not replace the package logger")
	}
	logger.Printf("hi %d", 1)
	logger.Println("hi")
	if cap.printfCalls != 1 || cap.printlnCalls != 1 {
		t.Errorf("logger not used: printf=%d println=%d", cap.printfCalls, cap.printlnCalls)
	}

	// A nil logger must be ignored, leaving the current logger in place.
	SetLogger(nil)
	if logger != cap {
		t.Error("SetLogger(nil) replaced the logger")
	}
}

func TestWithConnectivityTimeout(t *testing.T) {
	if o := newConfigOptions(WithConnectivityTimeout(5 * time.Second)); o.connectivityTimeout != 5*time.Second {
		t.Errorf("connectivityTimeout = %v, want 5s", o.connectivityTimeout)
	}
	// Non-positive values must not clobber the default.
	if o := newConfigOptions(WithConnectivityTimeout(0)); o.connectivityTimeout != defaultConnectivityTimeout {
		t.Errorf("zero WithConnectivityTimeout changed default to %v", o.connectivityTimeout)
	}
}

func TestWithPingCount(t *testing.T) {
	if o := newConfigOptions(WithPingCount(3)); o.pingCount != 3 {
		t.Errorf("pingCount = %d, want 3", o.pingCount)
	}
	// Non-positive values must not clobber the default.
	if o := newConfigOptions(WithPingCount(0)); o.pingCount != defaultPingCount {
		t.Errorf("zero WithPingCount changed default to %d", o.pingCount)
	}
}

func TestWithPingTimeout(t *testing.T) {
	if o := newConfigOptions(WithPingTimeout(30 * time.Second)); o.pingTimeout != 30*time.Second {
		t.Errorf("pingTimeout = %v, want 30s", o.pingTimeout)
	}
	if o := newConfigOptions(WithPingTimeout(0)); o.pingTimeout != defaultPingTimeout {
		t.Errorf("zero WithPingTimeout changed default to %v", o.pingTimeout)
	}
}

func TestWithBackupRetention(t *testing.T) {
	if o := newConfigOptions(WithBackupRetention(10)); o.backupRetention != 10 {
		t.Errorf("backupRetention = %d, want 10", o.backupRetention)
	}
	// Zero/negative disables pruning (keeps all backups).
	if o := newConfigOptions(WithBackupRetention(0)); o.backupRetention != 0 {
		t.Errorf("backupRetention = %d, want 0", o.backupRetention)
	}
}

func TestWithAllowPrimaryRemoval(t *testing.T) {
	if o := newConfigOptions(WithAllowPrimaryRemoval(true)); !o.allowPrimaryRemoval {
		t.Error("WithAllowPrimaryRemoval(true) did not set allowPrimaryRemoval")
	}
}

func TestWithSkipPanels(t *testing.T) {
	if o := newConfigOptions(WithSkipPanels(true)); !o.skipPanels {
		t.Error("WithSkipPanels(true) did not set skipPanels")
	}
	if o := newConfigOptions(WithSkipPanels(false)); o.skipPanels {
		t.Error("WithSkipPanels(false) set skipPanels")
	}
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
	if failing.dnsCalls != 1 || ok.dnsCalls != 1 {
		t.Errorf("dns calls: failing=%d ok=%d, want 1 each", failing.dnsCalls, ok.dnsCalls)
	}
}

func TestIPStrings(t *testing.T) {
	got := ipStrings([]net.IP{net.ParseIP("8.8.8.8"), nil, net.ParseIP("2001:4860:4860::8888")})
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if len(got) != len(want) {
		t.Fatalf("ipStrings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ipStrings[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestNetplanDNS round-trips DNS through the netplan backend: SetIfaceDNS writes
// the nameservers block and GetInterfaces parses it back.
func TestNetplanDNS(t *testing.T) {
	tmpDir := t.TempDir()
	config := "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [192.0.2.10/24]\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "01-test.yaml"), []byte(config), 0644); err != nil {
		t.Fatal(err)
	}

	np, err := readNetplanConfigDirectory(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	servers := []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("2001:4860:4860::8888")}
	if err := np.SetIfaceDNS(context.Background(), "eth0", servers, []string{"example.com", "corp.example"}); err != nil {
		t.Fatal(err)
	}

	// Re-read from disk so we exercise the written config, not in-memory state.
	np, err = readNetplanConfigDirectory(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	ifaces, err := np.GetInterfaces()
	if err != nil {
		t.Fatal(err)
	}

	var eth0 *Interface
	for _, i := range ifaces {
		if i.Name == "eth0" {
			eth0 = i
		}
	}
	if eth0 == nil {
		t.Fatal("eth0 not found after SetIfaceDNS")
	}
	if len(eth0.DNS) != 2 || !eth0.DNS[0].Equal(servers[0]) || !eth0.DNS[1].Equal(servers[1]) {
		t.Errorf("DNS = %v, want %v", eth0.DNS, servers)
	}
	if len(eth0.SearchDomains) != 2 || eth0.SearchDomains[0] != "example.com" || eth0.SearchDomains[1] != "corp.example" {
		t.Errorf("SearchDomains = %v, want [example.com corp.example]", eth0.SearchDomains)
	}
}
