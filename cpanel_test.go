package netconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// parseJSON unmarshals a single line of whmapi1 output; verify its guard on
// the expected single-line shape and that valid/invalid JSON behave correctly.
func TestCpanelParseJSON(t *testing.T) {
	c := &cpanel{}

	t.Run("valid single line", func(t *testing.T) {
		var v cpanelBase
		err := c.parseJSON([]string{`{"metadata":{"command":"listips","result":1}}`}, &v)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v.Metadata.Command != "listips" || v.Metadata.Result != 1 {
			t.Errorf("decoded = %+v, want command=listips result=1", v.Metadata)
		}
	})

	t.Run("no output errors", func(t *testing.T) {
		var v cpanelBase
		if err := c.parseJSON(nil, &v); err == nil {
			t.Error("expected error for empty output")
		}
	})

	t.Run("multiple lines errors", func(t *testing.T) {
		var v cpanelBase
		if err := c.parseJSON([]string{"{}", "{}"}, &v); err == nil {
			t.Error("expected error for multi-line output")
		}
	})

	t.Run("invalid json errors", func(t *testing.T) {
		var v cpanelBase
		if err := c.parseJSON([]string{"not json"}, &v); err == nil {
			t.Error("expected error for invalid json")
		}
	})
}

// setWWWAcctAddr repoints an address directive (ADDR / ADDR6) in wwwacct.conf;
// verify it replaces the value in place, appends when absent, and that ADDR and
// ADDR6 are set independently without disturbing each other.
func TestSetWWWAcctAddr(t *testing.T) {
	t.Run("replaces existing ADDR and preserves other lines", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		content := "HOST server.example.com\nADDR 203.0.113.10\nNS ns1.example.com\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if err := setWWWAcctAddr(path, "ADDR", "203.0.113.20"); err != nil {
			t.Fatalf("setWWWAcctAddr: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "HOST server.example.com\nADDR 203.0.113.20\nNS ns1.example.com\n"
		if string(got) != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("appends ADDR when absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		if err := os.WriteFile(path, []byte("HOST server.example.com\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := setWWWAcctAddr(path, "ADDR", "203.0.113.20"); err != nil {
			t.Fatalf("setWWWAcctAddr: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "HOST server.example.com\nADDR 203.0.113.20\n"
		if string(got) != want {
			t.Errorf("got:\n%q\nwant:\n%q", got, want)
		}
	})

	t.Run("setting ADDR does not touch ADDR6", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		content := "ADDR 203.0.113.10\nADDR6 2001:db8::1\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if err := setWWWAcctAddr(path, "ADDR", "203.0.113.20"); err != nil {
			t.Fatalf("setWWWAcctAddr: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "ADDR 203.0.113.20\nADDR6 2001:db8::1\n"
		if string(got) != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("setting ADDR6 replaces it and leaves ADDR alone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		content := "ADDR 203.0.113.10\nADDR6 2001:db8::1\n"
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if err := setWWWAcctAddr(path, "ADDR6", "2001:db8::20"); err != nil {
			t.Fatalf("setWWWAcctAddr: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "ADDR 203.0.113.10\nADDR6 2001:db8::20\n"
		if string(got) != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("appends ADDR6 when absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		if err := os.WriteFile(path, []byte("ADDR 203.0.113.10\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := setWWWAcctAddr(path, "ADDR6", "2001:db8::20"); err != nil {
			t.Fatalf("setWWWAcctAddr: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "ADDR 203.0.113.10\nADDR6 2001:db8::20\n"
		if string(got) != want {
			t.Errorf("got:\n%s\nwant:\n%s", got, want)
		}
	})
}
