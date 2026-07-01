package netconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readIfcfg parses a written ifcfg-<iface> file back into a key/value map so
// tests can assert on individual directives (PEERDNS, DNS1, ...).
func readIfcfg(t *testing.T, dir, iface string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "ifcfg-"+iface))
	require.NoError(t, err)
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
	require.NoError(t, err)
	cfg := readIfcfg(t, dir, "eth0")
	assert.Equal(t, "no", cfg["PEERDNS"])
	assert.Equal(t, "1.1.1.1", cfg["DNS1"])
	assert.Equal(t, "8.8.8.8", cfg["DNS2"])
	assert.Equal(t, "example.com", cfg["DOMAIN"])

	// Clearing DNS should drop PEERDNS so DHCP-provided resolvers resume.
	err = ns.SetIfaceDNS(context.Background(), "eth0", nil, nil)
	require.NoError(t, err)
	cfg = readIfcfg(t, dir, "eth0")
	_, ok := cfg["PEERDNS"]
	assert.False(t, ok)
	_, ok = cfg["DNS1"]
	assert.False(t, ok)
}

// TestIfUpDownDNSEnsuresInterface verifies that SetIfaceDNS creates the
// interface block when it has not been seen before, rather than silently
// no-opping and reporting success with nothing persisted.
func TestIfUpDownDNSEnsuresInterface(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "interfaces")
	err := os.WriteFile(cfgPath, []byte("auto lo\niface lo inet loopback\n"), 0644)
	require.NoError(t, err)
	i := &ifUpDown{BaseConfig: cfgPath, BackupDir: cfgPath + ".backup"}
	require.NoError(t, i.ReadFile(cfgPath))

	// eth0 is not present in the file; SetIfaceDNS must create it.
	err = i.SetIfaceDNS(context.Background(), "eth0",
		[]net.IP{net.ParseIP("1.1.1.1")}, []string{"example.com"})
	require.NoError(t, err)

	// Re-read from disk and confirm the stanzas were persisted.
	i.Interfaces = nil
	require.NoError(t, i.ReadFile(cfgPath))
	interfaces, err := i.GetInterfaces()
	require.NoError(t, err)
	var found *Interface
	for _, iface := range interfaces {
		if iface.Name == "eth0" {
			found = iface
			break
		}
	}
	require.NotNil(t, found, "eth0 was not persisted; SetIfaceDNS silently no-opped")
	require.Len(t, found.DNS, 1)
	assert.True(t, found.DNS[0].Equal(net.ParseIP("1.1.1.1")), "DNS = %v, want [1.1.1.1]", found.DNS)
	assert.Equal(t, []string{"example.com"}, found.SearchDomains)
}
