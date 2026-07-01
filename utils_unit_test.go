package netconfig

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Round-tripping an IPv4 address through ip2Uint/uint2IP must return the
// original four-byte value.
func TestIP2UintRoundTrip(t *testing.T) {
	cases := []string{"0.0.0.0", "1.2.3.4", "192.168.1.255", "255.255.255.255"}
	for _, c := range cases {
		ip := net.ParseIP(c)
		require.NotNil(t, ip, "could not parse %q", c)
		got := uint2IP(ip2Uint(ip))
		assert.True(t, got.Equal(ip), "round trip of %s: got %s", c, got)
		// uint2IP should produce the canonical four-byte representation.
		assert.Equal(t, net.IPv4len, len(got), "uint2IP(%s) length", c)
	}
}

// ip2Uint must accept both the 16-byte and 4-byte representations of the same
// IPv4 address and yield an identical result.
func TestIP2UintAcceptsBothRepresentations(t *testing.T) {
	ip16 := net.ParseIP("10.20.30.40")
	ip4 := ip16.To4()
	require.NotNil(t, ip4, "expected an IPv4 address")
	assert.Equal(t, ip2Uint(ip16), ip2Uint(ip4),
		"ip2Uint disagrees for 16-byte and 4-byte forms")
}

func TestAllFF(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte{}, true},
		{[]byte{0xff}, true},
		{[]byte{0xff, 0xff, 0xff, 0xff}, true},
		{[]byte{0xff, 0x00}, false},
		{[]byte{0x00}, false},
		{[]byte{0xff, 0xff, 0xfe}, false},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, allFF(c.in), "allFF(%v)", c.in)
	}
}

func TestGetBroadcast(t *testing.T) {
	cases := []struct {
		cidr string
		want string
	}{
		{"192.168.1.0/24", "192.168.1.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"172.16.5.0/30", "172.16.5.3"},
		{"203.0.113.128/25", "203.0.113.255"},
		{"fc00::/64", "fc00::ffff:ffff:ffff:ffff"},
	}
	for _, c := range cases {
		_, network, err := net.ParseCIDR(c.cidr)
		require.NoError(t, err, "ParseCIDR(%q)", c.cidr)
		got := getBroadcast(network)
		want := net.ParseIP(c.want)
		assert.True(t, got.Equal(want), "getBroadcast(%s) = %s, want %s", c.cidr, got, c.want)
	}
}

// getBroadcast must cope with an IPv4 address paired with an IPv4-in-IPv6 mask,
// exercising the family-normalisation branch.
func TestGetBroadcastMixedFamily(t *testing.T) {
	network := &net.IPNet{
		IP:   net.ParseIP("192.168.1.0").To4(),
		Mask: net.CIDRMask(96+24, 128), // /24 expressed as a 16-byte mask.
	}
	got := getBroadcast(network)
	want := net.ParseIP("192.168.1.255")
	assert.True(t, got.Equal(want), "getBroadcast mixed family = %s, want %s", got, want)
}

func TestSortableDirEntries(t *testing.T) {
	dir := t.TempDir()
	names := []string{"zebra", "alpha", "mike", "bravo"}
	for _, n := range names {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), nil, 0o644))
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	// Shuffle into a known unsorted order before sorting.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})

	sortable := sortableDirEntries(entries)
	assert.Equal(t, len(names), sortable.Len(), "Len()")
	sort.Sort(sortable)

	want := []string{"alpha", "bravo", "mike", "zebra"}
	for i, w := range want {
		assert.Equal(t, w, entries[i].Name(), "sorted[%d]", i)
	}
}

func TestIntStringYAML(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		var v intString
		require.NoError(t, yaml.Unmarshal([]byte("42\n"), &v))
		require.NotNil(t, v.Int, "Int = %v, want 42", v.Int)
		assert.Equal(t, 42, *v.Int)
		assert.Nil(t, v.String, "String should be nil")
		out, err := yaml.Marshal(v)
		require.NoError(t, err)
		assert.Equal(t, "42\n", string(out), "marshal")
	})

	t.Run("string", func(t *testing.T) {
		var v intString
		require.NoError(t, yaml.Unmarshal([]byte("auto\n"), &v))
		require.NotNil(t, v.String, "String = %v, want auto", v.String)
		assert.Equal(t, "auto", *v.String)
		assert.Nil(t, v.Int, "Int should be nil")
		out, err := yaml.Marshal(v)
		require.NoError(t, err)
		assert.Equal(t, "auto\n", string(out), "marshal")
	})

	t.Run("empty marshals to null", func(t *testing.T) {
		out, err := yaml.Marshal(intString{})
		require.NoError(t, err)
		assert.Equal(t, "null\n", string(out), "marshal of empty")
	})
}

func TestIntStringJSON(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		var v intString
		require.NoError(t, json.Unmarshal([]byte("42"), &v))
		require.NotNil(t, v.Int, "Int = %v, want 42", v.Int)
		assert.Equal(t, 42, *v.Int)
		out, err := json.Marshal(v)
		require.NoError(t, err)
		assert.Equal(t, "42", string(out), "marshal")
	})

	t.Run("string", func(t *testing.T) {
		var v intString
		require.NoError(t, json.Unmarshal([]byte(`"auto"`), &v))
		require.NotNil(t, v.String, "String = %v, want auto", v.String)
		assert.Equal(t, "auto", *v.String)
		out, err := json.Marshal(v)
		require.NoError(t, err)
		assert.Equal(t, `"auto"`, string(out), "marshal")
	})

	t.Run("invalid", func(t *testing.T) {
		var v intString
		err := json.Unmarshal([]byte("{}"), &v)
		assert.Error(t, err, "expected error for object input, got nil")
	})
}

func TestRunCommand(t *testing.T) {
	t.Run("stdout", func(t *testing.T) {
		out, err := runCommand(context.Background(), "printf", "line1\nline2\n")
		require.NoError(t, err, "unexpected error")
		want := []string{"line1", "line2"}
		assert.Equal(t, want, out, "out")
	})

	t.Run("nonzero exit", func(t *testing.T) {
		_, err := runCommand(context.Background(), "false")
		assert.Error(t, err, "expected error for failing command, got nil")
	})

	t.Run("missing binary", func(t *testing.T) {
		_, err := runCommand(context.Background(), "this-binary-should-not-exist-12345")
		assert.Error(t, err, "expected error for missing binary, got nil")
	})
}

func TestTestInternet(t *testing.T) {
	assert.True(t, testInternet(context.Background(), "test_success", 0),
		"test_success sentinel should report success")
	assert.False(t, testInternet(context.Background(), "test_fail", 0),
		"test_fail sentinel should report failure")
}

func TestFileCopyAndMove(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	content := []byte("hello world\n")
	require.NoError(t, os.WriteFile(src, content, 0o640))

	t.Run("fileCopy preserves contents and mode", func(t *testing.T) {
		dst := filepath.Join(dir, "copy.txt")
		require.NoError(t, fileCopy(src, dst))
		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, content, got, "copied contents")
		fi, err := os.Stat(dst)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o640), fi.Mode().Perm(), "copied mode")
	})

	t.Run("fileCopy missing source errors", func(t *testing.T) {
		err := fileCopy(filepath.Join(dir, "nope"), filepath.Join(dir, "out"))
		assert.Error(t, err, "expected error for missing source")
	})

	t.Run("fileMoveCopy removes source", func(t *testing.T) {
		moveSrc := filepath.Join(dir, "movesrc.txt")
		require.NoError(t, os.WriteFile(moveSrc, content, 0o644))
		dst := filepath.Join(dir, "moved.txt")
		require.NoError(t, fileMoveCopy(moveSrc, dst))
		_, err := os.Stat(moveSrc)
		assert.True(t, os.IsNotExist(err), "source should be gone, stat err = %v", err)
		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, content, got, "moved contents")
	})

	t.Run("fileMove same device renames", func(t *testing.T) {
		moveSrc := filepath.Join(dir, "rename-src.txt")
		require.NoError(t, os.WriteFile(moveSrc, content, 0o644))
		dst := filepath.Join(dir, "renamed.txt")
		require.NoError(t, fileMove(moveSrc, dst))
		_, err := os.Stat(moveSrc)
		assert.True(t, os.IsNotExist(err), "source should be gone after move, stat err = %v", err)
		_, err = os.Stat(dst)
		assert.NoError(t, err, "destination missing after move")
	})
}

func TestNaturalLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		why  string
	}{
		{"eth2", "eth10", true, "digit runs compare by value, not character"},
		{"eth10", "eth2", false, "reversed"},
		{"eth0", "eth1", true, "same width digits"},
		{"enp0s3", "enp0s10", true, "embedded digit runs"},
		{"eth0", "eth0", false, "equal strings are not less"},
		{"eth", "eth0", true, "a prefix sorts before what extends it"},
		{"eth0", "eth", false, "reversed prefix"},
		{"eth007", "eth7", false, "leading zeros do not change the value"},
		{"eth7", "eth007", false, "reversed equal values"},
		{"eth1", "wlan0", true, "letters compare by byte"},
		{"9", "10", true, "bare numbers"},
		{"eth99999999999999999999", "eth999999999999999999999", true, "digit runs too long to parse"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, naturalLess(c.a, c.b), "naturalLess(%q, %q): %s", c.a, c.b, c.why)
	}
}

func TestLeadingDigits(t *testing.T) {
	digits, rest := leadingDigits("10s3")
	assert.Equal(t, "10", digits)
	assert.Equal(t, "s3", rest)

	digits, rest = leadingDigits("eth0")
	assert.Empty(t, digits)
	assert.Equal(t, "eth0", rest)
}
