package netconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNodeworxChoices reads option values from nodeworx 5's help, as printed on
// a CentOS 6 InterWorx host.
func TestNodeworxChoices(t *testing.T) {
	help := func(ip string) []string {
		return []string{
			"Usage: nodeworx.php Ip import [ options ]",
			"--help|-h                Display this help and exit",
			"--output-style|-o <word> default|json|pretty|yaml - default=tab delimited, json=compact json, pretty=human readable json, yaml=yaml",
			"--ip <string>            " + ip,
		}
	}
	tests := []struct {
		name string
		help []string
		want []string
	}{
		{"nothing to import", help(""), nil},
		{"one address", help("192.0.2.77"), []string{"192.0.2.77"}},
		{"several addresses", help("192.0.2.77|2001:db8::77"), []string{"192.0.2.77", "2001:db8::77"}},
		{"option missing", help("")[:3], nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, nodeworxChoices(tt.help, "--ip"))
		})
	}
}
