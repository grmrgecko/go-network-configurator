//go:build linux

package netconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// absentService is a service name no host can plausibly have registered, so
// sysvServiceEnabled is guaranteed to answer false for it. It lets the systemd
// branches of initState.enabled be tested without the SysV fallback ever
// masking the result.
const absentService = "netconfig-nonexistent-service"

// A unit file state systemd owns outright is authoritative: only "enabled" and
// "enabled-runtime" count, and the SysV fallback is never consulted.
func TestInitStateEnabledTrustsSystemdUnitFileState(t *testing.T) {
	ctx := context.Background()
	cases := map[string]bool{
		"enabled":         true,
		"enabled-runtime": true,
		"disabled":        false,
		"static":          false,
		"masked":          false,
	}
	for state, want := range cases {
		s := &initState{
			active:    map[string]bool{},
			unitFiles: map[string]string{absentService + ".service": state},
		}
		assert.Equal(t, want, s.enabled(ctx, absentService),
			"unit file state %q", state)
	}
}

// A "generated" unit is a systemd-sysv-generator wrapper around an init.d
// script. It carries no enablement of its own, so it must not be read as
// enabled — RHEL 7 ships network.service that way whether or not chkconfig has
// it on. Enablement has to come from the SysV registration, which for a service
// no host has is absent.
func TestInitStateEnabledDoesNotTrustGeneratedUnits(t *testing.T) {
	s := &initState{
		active:    map[string]bool{},
		unitFiles: map[string]string{absentService + ".service": "generated"},
	}
	assert.False(t, s.enabled(context.Background(), absentService),
		"a generated unit with no SysV registration must not read as enabled")
}

// A service systemd has never heard of falls through to the SysV mechanisms
// rather than being reported as disabled.
func TestInitStateEnabledFallsBackForUnknownUnits(t *testing.T) {
	s := &initState{active: map[string]bool{}, unitFiles: map[string]string{}}
	assert.False(t, s.enabled(context.Background(), absentService))
}

// detected is the union of running and enabled. Enablement must count on its
// own: a manager that is enabled but has not started this boot never appears in
// systemd's ListUnits, yet it owns the network after the next reboot and its
// configuration still has to be written. Equally, a manager that is running but
// disabled owns the network right now.
func TestInitStateDetectedUnionsRunningAndEnabled(t *testing.T) {
	ctx := context.Background()
	unit := absentService + ".service"

	enabledNotRunning := &initState{
		active:    map[string]bool{},
		unitFiles: map[string]string{unit: "enabled"},
	}
	assert.True(t, enabledNotRunning.detected(ctx, absentService),
		"an enabled service that is not running must be detected")

	runningNotEnabled := &initState{
		active:    map[string]bool{unit: true},
		unitFiles: map[string]string{unit: "disabled"},
	}
	assert.True(t, runningNotEnabled.detected(ctx, absentService),
		"a running service that is not enabled must be detected")

	neither := &initState{
		active:    map[string]bool{},
		unitFiles: map[string]string{unit: "disabled"},
	}
	assert.False(t, neither.detected(ctx, absentService))
}

// running reads systemd's active-unit set, keyed by the full unit name.
func TestInitStateRunning(t *testing.T) {
	s := &initState{
		active:    map[string]bool{"NetworkManager.service": true},
		unitFiles: map[string]string{},
	}
	assert.True(t, s.running("NetworkManager"))
	assert.False(t, s.running("systemd-networkd"))
}

// An S* start symlink in any rcN.d tree marks the service as enabled, in both
// the Debian/Ubuntu (/etc/rcN.d) and Slackware (/etc/rc.d/rcN.d) layouts. A K*
// kill symlink does not.
func TestRcSymlinksOnIn(t *testing.T) {
	for _, dir := range []string{"etc/rc2.d", "etc/rc.d/rc3.d", "etc/rc5.d"} {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
			require.NoError(t, os.WriteFile(
				filepath.Join(root, dir, "S01networking"), nil, 0o644))
			assert.True(t, rcSymlinksOnIn(root, "networking"))
			assert.False(t, rcSymlinksOnIn(root, "network"),
				"S01networking must not match the distinct service %q", "network")
		})
	}

	// A kill symlink means the service is stopped in that runlevel, not started.
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc/rc2.d"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "etc/rc2.d", "K01networking"), nil, 0o644))
	assert.False(t, rcSymlinksOnIn(root, "networking"))

	// Runlevels 0, 1, and 6 are halt, single-user, and reboot; nothing starts there.
	root = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc/rc1.d"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "etc/rc1.d", "S01networking"), nil, 0o644))
	assert.False(t, rcSymlinksOnIn(root, "networking"))

	assert.False(t, rcSymlinksOnIn(t.TempDir(), "networking"),
		"an empty root has no enabled services")
}

// OpenRC records enablement as a symlink into a runlevel directory.
func TestOpenrcOnIn(t *testing.T) {
	for _, rl := range []string{"default", "boot"} {
		t.Run(rl, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Join(root, "etc/runlevels", rl), 0o755))
			require.NoError(t, os.Symlink("/etc/init.d/net.lo",
				filepath.Join(root, "etc/runlevels", rl, "net.lo")))
			assert.True(t, openrcOnIn(root, "net.lo"))
			assert.False(t, openrcOnIn(root, "NetworkManager"))
		})
	}

	// A dangling symlink still marks the service as added to the runlevel, so
	// Lstat (not Stat) is what openrcOnIn must use.
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc/runlevels/default"), 0o755))
	require.NoError(t, os.Symlink("/nonexistent",
		filepath.Join(root, "etc/runlevels/default/dangling")))
	assert.True(t, openrcOnIn(root, "dangling"))

	assert.False(t, openrcOnIn(t.TempDir(), "net.lo"))
}

// Every service name detection asks systemd about must be in networkServiceUnits,
// since that list is what the unit-file lookup is filtered by. A name missing
// from it silently loses its systemd answer.
func TestNetworkServiceUnitsCoversDetectedServices(t *testing.T) {
	for _, name := range []string{"systemd-networkd", "NetworkManager", "network", "networking"} {
		assert.Contains(t, networkServiceUnits, name)
	}
}
