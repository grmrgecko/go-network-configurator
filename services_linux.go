//go:build linux

package netconfig

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	dbus "github.com/coreos/go-systemd/v22/dbus"
)

// rcRunlevels are the SysV runlevels a network service can be started in.
// Runlevels 0, 1, and 6 are halt, single-user, and reboot, so nothing is
// registered to start there.
var rcRunlevels = []string{"2", "3", "4", "5"}

// systemdActive reports whether systemd is the running init (/run/systemd/system
// exists), the same marker systemctl uses to decide it can reach the manager.
// It is checked before dialing D-Bus so hosts running Upstart (Ubuntu 14.04) or
// SysVinit (CentOS 5/6) skip a connection that cannot usefully succeed.
func systemdActive() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// commandExists reports whether name resolves on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// chkconfigOn reports whether `chkconfig --list name` shows any runlevel on,
// the RHEL-family enablement signal. Returns false when chkconfig is absent.
func chkconfigOn(ctx context.Context, name string) bool {
	if !commandExists("chkconfig") {
		return false
	}
	results, err := runCommand(ctx, "chkconfig", "--list", name)
	if err != nil {
		return false
	}
	for _, line := range results {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != name {
			continue
		}
		for _, f := range fields[1:] {
			if _, status, found := strings.Cut(f, ":"); found && status == "on" {
				return true
			}
		}
	}
	return false
}

// rcRunlevelDirs returns the rcN.d directories under root that a start symlink
// can live in, covering both the Debian/Ubuntu layout (/etc/rcN.d) and the
// Slackware one (/etc/rc.d/rcN.d).
func rcRunlevelDirs(root string) []string {
	dirs := make([]string, 0, len(rcRunlevels)*2)
	for _, rl := range rcRunlevels {
		dirs = append(dirs,
			filepath.Join(root, "etc", "rc"+rl+".d"),
			filepath.Join(root, "etc", "rc.d", "rc"+rl+".d"),
		)
	}
	return dirs
}

// rcSymlinksOn reports whether an S*name start symlink exists in any rcN.d tree,
// the enablement signal for both update-rc.d (Debian/Ubuntu) and Slackware.
func rcSymlinksOn(name string) bool {
	return rcSymlinksOnIn("/", name)
}

// rcSymlinksOnIn is rcSymlinksOn rooted at root, so tests can build a runlevel
// tree in a temporary directory.
func rcSymlinksOnIn(root, name string) bool {
	for _, dir := range rcRunlevelDirs(root) {
		if matches, _ := filepath.Glob(filepath.Join(dir, "S*"+name)); len(matches) > 0 {
			return true
		}
	}
	return false
}

// openrcOn reports whether name is linked into an OpenRC runlevel directory
// (default or boot), the enablement signal created by `rc-update add` on Gentoo.
func openrcOn(name string) bool {
	return openrcOnIn("/", name)
}

// openrcOnIn is openrcOn rooted at root, so tests can build a runlevel tree in a
// temporary directory.
func openrcOnIn(root, name string) bool {
	for _, rl := range []string{"default", "boot"} {
		if _, err := os.Lstat(filepath.Join(root, "etc", "runlevels", rl, name)); err == nil {
			return true
		}
	}
	return false
}

// sysvServiceEnabled reports whether name is registered to start at boot under
// a SysV-family init system: chkconfig (RHEL), update-rc.d rcN.d start symlinks
// (Debian/Ubuntu/Slackware), or an OpenRC runlevel (Gentoo). name is the service
// base name without a ".service" suffix. Any one mechanism reporting it on
// counts as enabled.
func sysvServiceEnabled(ctx context.Context, name string) bool {
	return chkconfigOn(ctx, name) || rcSymlinksOn(name) || openrcOn(name)
}

// initSystemDiscoverable reports whether this host exposes any init system that
// sysvServiceEnabled or systemd can be asked about. It is false on minimal
// images and containers that have neither systemd nor chkconfig nor runlevel
// directories, where a backend's configuration file is the only evidence
// available and detection has nothing to corroborate it with.
func initSystemDiscoverable() bool {
	if systemdActive() || commandExists("chkconfig") {
		return true
	}
	for _, dir := range rcRunlevelDirs("/") {
		if _, err := os.Stat(dir); err == nil {
			return true
		}
	}
	_, err := os.Stat("/etc/runlevels")
	return err == nil
}

// networkServiceUnits are the services backend detection asks systemd about.
// They are collected here so the unit-file lookup can be filtered server side
// to just these names, which is orders of magnitude cheaper than listing every
// unit file on the host. Only these names may be passed to initState.enabled
// and initState.detected; any other name silently skips the systemd answer and
// falls through to the SysV mechanisms.
var networkServiceUnits = []string{"systemd-networkd", "NetworkManager", "network", "networking"}

// initState is a snapshot of what the host's init system reports about its
// units, taken once when the configurator is constructed. Each systemd query
// costs a D-Bus round trip, so the running units and the installed unit files
// are both fetched up front and every per-service question is answered from
// memory afterwards.
type initState struct {
	// active holds the unit names ("NetworkManager.service") systemd reports as
	// currently running. Empty when systemd could not be queried.
	active map[string]bool
	// unitFiles maps an installed unit file's base name to its UnitFileState
	// ("enabled", "disabled", "generated", ...). A unit that is enabled but was
	// never loaded this boot appears here and not in active, which is why both
	// are read. Empty when systemd could not be queried.
	unitFiles map[string]string
}

// newInitState queries systemd for the host's running units and installed unit
// files. Every step degrades to an empty map rather than an error: a host that
// cannot answer over D-Bus is not broken, it is a host whose services must be
// discovered through the SysV mechanisms instead, which enabled falls back to.
// The queries are bound by ctx so a wedged systemd cannot stall construction.
func newInitState(ctx context.Context) *initState {
	s := &initState{
		active:    make(map[string]bool),
		unitFiles: make(map[string]string),
	}

	// Skip D-Bus entirely when systemd is not the running init. On Ubuntu 14.04
	// Upstart is PID 1 and org.freedesktop.systemd1 is served by systemd-shim,
	// which accepts the connection but has no ListUnits; on CentOS 5/6 there is
	// no systemd1 on the bus at all. Both would otherwise cost a failed dial and
	// a failed call before reaching the SysV checks that were always going to
	// answer for them.
	if !systemdActive() {
		return s
	}

	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		logger.Printf("unable to connect to systemd, falling back to init-script detection: %v", err)
		return s
	}
	defer conn.Close()

	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		logger.Printf("unable to list systemd units, falling back to init-script detection: %v", err)
	}
	for _, unit := range units {
		if unit.ActiveState == "active" {
			s.active[unit.Name] = true
		}
	}

	// The unit files report enablement, including for units that are enabled but
	// have not been loaded this boot and so never appear in ListUnits.
	//
	// ListUnitFilesByPatterns filters server side and answers in milliseconds;
	// ListUnitFiles walks every unit file on the host and can take seconds on a
	// machine with a few hundred of them. Only systemd 230 and later export the
	// filtered call, so fall back to the full listing for older systemd (CentOS
	// 7 ships 219). Both are read into the same map keyed by unit file name.
	patterns := make([]string, 0, len(networkServiceUnits))
	for _, name := range networkServiceUnits {
		patterns = append(patterns, name+".service")
	}
	files, err := conn.ListUnitFilesByPatternsContext(ctx, nil, patterns)
	if err != nil {
		files, err = conn.ListUnitFilesContext(ctx)
	}
	if err != nil {
		logger.Printf("unable to list systemd unit files, falling back to init-script detection: %v", err)
		return s
	}
	for _, uf := range files {
		s.unitFiles[filepath.Base(uf.Path)] = uf.Type
	}
	return s
}

// running reports whether systemd has name's service unit active right now.
func (s *initState) running(name string) bool {
	return s.active[name+".service"]
}

// enabled reports whether name is registered to start at boot. systemd's
// UnitFileState is authoritative when it owns the unit outright; a "generated"
// state is not, because systemd-sysv-generator wraps an /etc/init.d script into
// a unit that carries no enablement of its own. RHEL 7 ships network.service
// that way whether or not chkconfig has it on, so a generated unit's real
// enablement is read from its SysV registration, as is any unit systemd has
// never heard of.
func (s *initState) enabled(ctx context.Context, name string) bool {
	state, known := s.unitFiles[name+".service"]
	if known && state != "generated" {
		return state == "enabled" || state == "enabled-runtime"
	}
	return sysvServiceEnabled(ctx, name)
}

// detected reports whether name's service manages this host's network: either
// it is running now, or it is registered to start at boot. Enablement counts
// independently of the running state because this package writes configuration
// that must survive a reboot. A manager that is enabled but not yet started —
// a host mid-provision, a chroot, an image build, a unit whose start failed —
// still owns the network on the next boot, and systemd's ListUnits does not
// report it at all.
func (s *initState) detected(ctx context.Context, name string) bool {
	return s.running(name) || s.enabled(ctx, name)
}

// networkManagerRunning reports whether NetworkManager's daemon left a runtime
// pid file. It is the running-state signal on hosts where systemd cannot be
// queried, and is unioned with the systemd signals rather than replacing them,
// so a partial answer from systemd never hides a manager this can still see.
func networkManagerRunning() bool {
	for _, pidFile := range []string{
		"/var/run/NetworkManager/NetworkManager.pid",
		"/run/NetworkManager/NetworkManager.pid",
	} {
		if _, err := os.Stat(pidFile); err == nil {
			return true
		}
	}
	return false
}
