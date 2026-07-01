package netconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseJSON unmarshals a single line of whmapi1 output; verify its guard on
// the expected single-line shape and that valid/invalid JSON behave correctly.
func TestCpanelParseJSON(t *testing.T) {
	c := &cpanel{}

	t.Run("valid single line", func(t *testing.T) {
		var v cpanelBase
		err := c.parseJSON([]string{`{"metadata":{"command":"listips","result":1}}`}, &v)
		require.NoError(t, err)
		assert.Equal(t, "listips", v.Metadata.Command)
		assert.Equal(t, 1, v.Metadata.Result)
	})

	t.Run("no output errors", func(t *testing.T) {
		var v cpanelBase
		assert.Error(t, c.parseJSON(nil, &v))
	})

	t.Run("multiple lines errors", func(t *testing.T) {
		var v cpanelBase
		assert.Error(t, c.parseJSON([]string{"{}", "{}"}, &v))
	})

	t.Run("invalid json errors", func(t *testing.T) {
		var v cpanelBase
		assert.Error(t, c.parseJSON([]string{"not json"}, &v))
	})
}

// setWWWAcctAddr repoints an address directive (ADDR / ADDR6) in wwwacct.conf;
// verify it replaces the value in place, appends when absent, and that ADDR and
// ADDR6 are set independently without disturbing each other.
func TestSetWWWAcctAddr(t *testing.T) {
	t.Run("replaces existing ADDR and preserves other lines", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		content := "HOST server.example.com\nADDR 203.0.113.10\nNS ns1.example.com\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
		require.NoError(t, setWWWAcctAddr(path, "ADDR", "203.0.113.20"))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		want := "HOST server.example.com\nADDR 203.0.113.20\nNS ns1.example.com\n"
		assert.Equal(t, want, string(got))
	})

	t.Run("appends ADDR when absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		require.NoError(t, os.WriteFile(path, []byte("HOST server.example.com\n"), 0644))
		require.NoError(t, setWWWAcctAddr(path, "ADDR", "203.0.113.20"))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		want := "HOST server.example.com\nADDR 203.0.113.20\n"
		assert.Equal(t, want, string(got))
	})

	t.Run("setting ADDR does not touch ADDR6", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		content := "ADDR 203.0.113.10\nADDR6 2001:db8::1\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
		require.NoError(t, setWWWAcctAddr(path, "ADDR", "203.0.113.20"))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		want := "ADDR 203.0.113.20\nADDR6 2001:db8::1\n"
		assert.Equal(t, want, string(got))
	})

	t.Run("setting ADDR6 replaces it and leaves ADDR alone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		content := "ADDR 203.0.113.10\nADDR6 2001:db8::1\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0644))
		require.NoError(t, setWWWAcctAddr(path, "ADDR6", "2001:db8::20"))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		want := "ADDR 203.0.113.10\nADDR6 2001:db8::20\n"
		assert.Equal(t, want, string(got))
	})

	t.Run("appends ADDR6 when absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wwwacct.conf")
		require.NoError(t, os.WriteFile(path, []byte("ADDR 203.0.113.10\n"), 0644))
		require.NoError(t, setWWWAcctAddr(path, "ADDR6", "2001:db8::20"))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		want := "ADDR 203.0.113.10\nADDR6 2001:db8::20\n"
		assert.Equal(t, want, string(got))
	})
}
