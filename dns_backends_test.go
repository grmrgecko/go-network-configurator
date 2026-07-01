package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// readIfcfg parses a written ifcfg-<iface> file back into a key/value map so
// tests can assert on individual directives (PEERDNS, DNS1, ...).
func readIfcfg(t *testing.T, dir, iface string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "ifcfg-"+iface))
	if err != nil {
		t.Fatalf("read ifcfg-%s: %v", iface, err)
	}
	out := make(map[string]string)
	for _, line := range splitLines(string(data)) {
		k, v, ok := cutKV(line)
		if ok {
			out[k] = v
		}
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func cutKV(line string) (string, string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			v := line[i+1:]
			// Strip surrounding quotes written for values with whitespace.
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			return line[:i], v, true
		}
	}
	return "", "", false
}

// TestNetworkScriptsDNSPeerDNS verifies that setting DNS on a network-scripts
// interface writes PEERDNS=no (so dhclient does not override the static
// resolvers) and that clearing DNS removes PEERDNS again.
func TestNetworkScriptsDNSPeerDNS(t *testing.T) {
	dir := t.TempDir()
	ns := &networkScripts{ConfigDir: dir}

	// Set DNS servers.
	err := ns.SetIfaceDNS(context.Background(), "eth0",
		[]net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")},
		[]string{"example.com"})
	if err != nil {
		t.Fatalf("SetIfaceDNS: %v", err)
	}
	cfg := readIfcfg(t, dir, "eth0")
	if cfg["PEERDNS"] != "no" {
		t.Errorf("PEERDNS = %q, want \"no\"", cfg["PEERDNS"])
	}
	if cfg["DNS1"] != "1.1.1.1" || cfg["DNS2"] != "8.8.8.8" {
		t.Errorf("DNS1/DNS2 = %q/%q, want 1.1.1.1/8.8.8.8", cfg["DNS1"], cfg["DNS2"])
	}
	if cfg["DOMAIN"] != "example.com" {
		t.Errorf("DOMAIN = %q, want example.com", cfg["DOMAIN"])
	}

	// Clearing DNS should drop PEERDNS so DHCP-provided resolvers resume.
	err = ns.SetIfaceDNS(context.Background(), "eth0", nil, nil)
	if err != nil {
		t.Fatalf("SetIfaceDNS clear: %v", err)
	}
	cfg = readIfcfg(t, dir, "eth0")
	if _, ok := cfg["PEERDNS"]; ok {
		t.Errorf("PEERDNS still present after clear: %q", cfg["PEERDNS"])
	}
	if _, ok := cfg["DNS1"]; ok {
		t.Errorf("DNS1 still present after clear: %q", cfg["DNS1"])
	}
}

// TestIfUpDownDNSEnsuresInterface verifies that SetIfaceDNS creates the
// interface block when it has not been seen before, rather than silently
// no-opping and reporting success with nothing persisted.
func TestIfUpDownDNSEnsuresInterface(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "interfaces")
	if err := os.WriteFile(cfgPath, []byte("auto lo\niface lo inet loopback\n"), 0644); err != nil {
		t.Fatal(err)
	}
	i := &ifUpDown{BaseConfig: cfgPath, BackupDir: cfgPath + ".backup"}
	if err := i.ReadFile(cfgPath); err != nil {
		t.Fatal(err)
	}

	// eth0 is not present in the file; SetIfaceDNS must create it.
	err := i.SetIfaceDNS(context.Background(), "eth0",
		[]net.IP{net.ParseIP("1.1.1.1")}, []string{"example.com"})
	if err != nil {
		t.Fatalf("SetIfaceDNS: %v", err)
	}

	// Re-read from disk and confirm the stanzas were persisted.
	i.Interfaces = nil
	if err := i.ReadFile(cfgPath); err != nil {
		t.Fatal(err)
	}
	interfaces, err := i.GetInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	var found *Interface
	for _, iface := range interfaces {
		if iface.Name == "eth0" {
			found = iface
			break
		}
	}
	if found == nil {
		t.Fatal("eth0 was not persisted; SetIfaceDNS silently no-opped")
	}
	if len(found.DNS) != 1 || !found.DNS[0].Equal(net.ParseIP("1.1.1.1")) {
		t.Errorf("DNS = %v, want [1.1.1.1]", found.DNS)
	}
	if len(found.SearchDomains) != 1 || found.SearchDomains[0] != "example.com" {
		t.Errorf("SearchDomains = %v, want [example.com]", found.SearchDomains)
	}
}
