package netconfig

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// Round-tripping an IPv4 address through ip2Uint/uint2IP must return the
// original four-byte value.
func TestIP2UintRoundTrip(t *testing.T) {
	cases := []string{"0.0.0.0", "1.2.3.4", "192.168.1.255", "255.255.255.255"}
	for _, c := range cases {
		ip := net.ParseIP(c)
		if ip == nil {
			t.Fatalf("could not parse %q", c)
		}
		got := uint2IP(ip2Uint(ip))
		if !got.Equal(ip) {
			t.Errorf("round trip of %s: got %s", c, got)
		}
		// uint2IP should produce the canonical four-byte representation.
		if len(got) != net.IPv4len {
			t.Errorf("uint2IP(%s) length = %d, want %d", c, len(got), net.IPv4len)
		}
	}
}

// ip2Uint must accept both the 16-byte and 4-byte representations of the same
// IPv4 address and yield an identical result.
func TestIP2UintAcceptsBothRepresentations(t *testing.T) {
	ip16 := net.ParseIP("10.20.30.40")
	ip4 := ip16.To4()
	if ip4 == nil {
		t.Fatal("expected an IPv4 address")
	}
	if ip2Uint(ip16) != ip2Uint(ip4) {
		t.Errorf("ip2Uint disagrees for 16-byte (%d) and 4-byte (%d) forms",
			ip2Uint(ip16), ip2Uint(ip4))
	}
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
		if got := allFF(c.in); got != c.want {
			t.Errorf("allFF(%v) = %v, want %v", c.in, got, c.want)
		}
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
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c.cidr, err)
		}
		got := getBroadcast(network)
		want := net.ParseIP(c.want)
		if !got.Equal(want) {
			t.Errorf("getBroadcast(%s) = %s, want %s", c.cidr, got, c.want)
		}
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
	if want := net.ParseIP("192.168.1.255"); !got.Equal(want) {
		t.Errorf("getBroadcast mixed family = %s, want %s", got, want)
	}
}

func TestSortableDirEntries(t *testing.T) {
	dir := t.TempDir()
	names := []string{"zebra", "alpha", "mike", "bravo"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Shuffle into a known unsorted order before sorting.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})

	sortable := sortableDirEntries(entries)
	if sortable.Len() != len(names) {
		t.Errorf("Len() = %d, want %d", sortable.Len(), len(names))
	}
	sort.Sort(sortable)

	want := []string{"alpha", "bravo", "mike", "zebra"}
	for i, w := range want {
		if entries[i].Name() != w {
			t.Errorf("sorted[%d] = %s, want %s", i, entries[i].Name(), w)
		}
	}
}

func TestIntStringYAML(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		var v intString
		if err := yaml.Unmarshal([]byte("42\n"), &v); err != nil {
			t.Fatal(err)
		}
		if v.Int == nil || *v.Int != 42 {
			t.Fatalf("Int = %v, want 42", v.Int)
		}
		if v.String != nil {
			t.Errorf("String should be nil, got %v", *v.String)
		}
		out, err := yaml.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(out); got != "42\n" {
			t.Errorf("marshal = %q, want %q", got, "42\n")
		}
	})

	t.Run("string", func(t *testing.T) {
		var v intString
		if err := yaml.Unmarshal([]byte("auto\n"), &v); err != nil {
			t.Fatal(err)
		}
		if v.String == nil || *v.String != "auto" {
			t.Fatalf("String = %v, want auto", v.String)
		}
		if v.Int != nil {
			t.Errorf("Int should be nil, got %v", *v.Int)
		}
		out, err := yaml.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(out); got != "auto\n" {
			t.Errorf("marshal = %q, want %q", got, "auto\n")
		}
	})

	t.Run("empty marshals to null", func(t *testing.T) {
		out, err := yaml.Marshal(intString{})
		if err != nil {
			t.Fatal(err)
		}
		if got := string(out); got != "null\n" {
			t.Errorf("marshal of empty = %q, want %q", got, "null\n")
		}
	})
}

func TestIntStringJSON(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		var v intString
		if err := json.Unmarshal([]byte("42"), &v); err != nil {
			t.Fatal(err)
		}
		if v.Int == nil || *v.Int != 42 {
			t.Fatalf("Int = %v, want 42", v.Int)
		}
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(out); got != "42" {
			t.Errorf("marshal = %q, want %q", got, "42")
		}
	})

	t.Run("string", func(t *testing.T) {
		var v intString
		if err := json.Unmarshal([]byte(`"auto"`), &v); err != nil {
			t.Fatal(err)
		}
		if v.String == nil || *v.String != "auto" {
			t.Fatalf("String = %v, want auto", v.String)
		}
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(out); got != `"auto"` {
			t.Errorf("marshal = %q, want %q", got, `"auto"`)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		var v intString
		if err := json.Unmarshal([]byte("{}"), &v); err == nil {
			t.Error("expected error for object input, got nil")
		}
	})
}

func TestRunCommand(t *testing.T) {
	t.Run("stdout", func(t *testing.T) {
		out, err := runCommand(context.Background(), "printf", "line1\nline2\n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"line1", "line2"}
		if !reflect.DeepEqual(out, want) {
			t.Errorf("out = %v, want %v", out, want)
		}
	})

	t.Run("nonzero exit", func(t *testing.T) {
		_, err := runCommand(context.Background(), "false")
		if err == nil {
			t.Error("expected error for failing command, got nil")
		}
	})

	t.Run("missing binary", func(t *testing.T) {
		_, err := runCommand(context.Background(), "this-binary-should-not-exist-12345")
		if err == nil {
			t.Error("expected error for missing binary, got nil")
		}
	})
}

func TestTestInternet(t *testing.T) {
	if !testInternet(context.Background(), "test_success", 0) {
		t.Error("test_success sentinel should report success")
	}
	if testInternet(context.Background(), "test_fail", 0) {
		t.Error("test_fail sentinel should report failure")
	}
}

func TestFileCopyAndMove(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	content := []byte("hello world\n")
	if err := os.WriteFile(src, content, 0o640); err != nil {
		t.Fatal(err)
	}

	t.Run("fileCopy preserves contents and mode", func(t *testing.T) {
		dst := filepath.Join(dir, "copy.txt")
		if err := fileCopy(src, dst); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, content) {
			t.Errorf("copied contents = %q, want %q", got, content)
		}
		fi, err := os.Stat(dst)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("copied mode = %v, want 0640", fi.Mode().Perm())
		}
	})

	t.Run("fileCopy missing source errors", func(t *testing.T) {
		if err := fileCopy(filepath.Join(dir, "nope"), filepath.Join(dir, "out")); err == nil {
			t.Error("expected error for missing source")
		}
	})

	t.Run("fileMoveCopy removes source", func(t *testing.T) {
		moveSrc := filepath.Join(dir, "movesrc.txt")
		if err := os.WriteFile(moveSrc, content, 0o644); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, "moved.txt")
		if err := fileMoveCopy(moveSrc, dst); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(moveSrc); !os.IsNotExist(err) {
			t.Errorf("source should be gone, stat err = %v", err)
		}
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, content) {
			t.Errorf("moved contents = %q, want %q", got, content)
		}
	})

	t.Run("fileMove same device renames", func(t *testing.T) {
		moveSrc := filepath.Join(dir, "rename-src.txt")
		if err := os.WriteFile(moveSrc, content, 0o644); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, "renamed.txt")
		if err := fileMove(moveSrc, dst); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(moveSrc); !os.IsNotExist(err) {
			t.Errorf("source should be gone after move, stat err = %v", err)
		}
		if _, err := os.Stat(dst); err != nil {
			t.Errorf("destination missing after move: %v", err)
		}
	})
}
