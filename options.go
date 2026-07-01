package netconfig

import (
	"time"

	log "github.com/sirupsen/logrus"
)

// Defaults for the tunable settings. They can be overridden with the
// corresponding With* Option when constructing a Configurator.
const (
	// defaultConnectivityTimeout bounds the HTTP reachability test run after an
	// address or gateway change so it cannot stall the rollback logic.
	defaultConnectivityTimeout = 10 * time.Second
	// defaultPingCount is the number of ICMP probes used to confirm a gateway or
	// candidate address is reachable.
	defaultPingCount = 5
	// defaultPingTimeout bounds a single ping run.
	defaultPingTimeout = 20 * time.Second
	// defaultBackupRetention is how many .bak.* copies are kept per original
	// configuration file. Older backups beyond this number are pruned on save.
	defaultBackupRetention = 5
)

// Logger is the minimal logging surface used across the package. It is
// satisfied by the standard library *log.Logger, logrus, and most other
// logging libraries, so callers can plug in their own logger via SetLogger.
type Logger interface {
	Printf(format string, args ...interface{})
	Println(args ...interface{})
}

// logger is the package-wide logger. It defaults to the logrus standard
// logger and can be replaced with SetLogger. It is package scoped because the
// configuration backends and control panels log independently of any single
// Configurator instance.
var logger Logger = log.StandardLogger()

// SetLogger replaces the package-wide logger used for non-fatal diagnostics.
// It is package scoped (not a per-Configurator option) because the configuration
// backends and control panels log independently of any single Configurator
// instance; the setting therefore applies to every Configurator in the process.
// A nil logger is ignored.
func SetLogger(l Logger) {
	if l != nil {
		logger = l
	}
}

// configOptions holds the tunable settings applied when constructing a
// Configurator. Use the With* Option helpers to set them.
type configOptions struct {
	// testAddress is the URL fetched to confirm connectivity after an
	// address or gateway change.
	testAddress string
	// skipConnectivityCheck disables the post-change internet reachability
	// test and its automatic rollback.
	skipConnectivityCheck bool
	// connectivityTimeout bounds the HTTP reachability test.
	connectivityTimeout time.Duration
	// pingCount is the number of ICMP probes per ping test.
	pingCount int
	// pingTimeout bounds a single ping run.
	pingTimeout time.Duration
	// backupRetention is the number of .bak.* copies kept per original
	// configuration file; <= 0 disables pruning (keeps all backups).
	backupRetention int
	// allowPrimaryRemoval lets RemoveAddress remove an address that is the
	// primary of its family, which is otherwise refused.
	allowPrimaryRemoval bool
	// skipPanels makes RemoveAddress bypass all control-panel backends
	// (cPanel/Plesk/InterWorx) and only remove the address from the running
	// system and the network-manager configuration files.
	skipPanels bool
}

// defaultConfigOptions returns the options used when no Option is supplied.
func defaultConfigOptions() *configOptions {
	return &configOptions{
		testAddress:         defaultInternetTestAddress,
		connectivityTimeout: defaultConnectivityTimeout,
		pingCount:           defaultPingCount,
		pingTimeout:         defaultPingTimeout,
		backupRetention:     defaultBackupRetention,
	}
}

// newConfigOptions builds a configOptions from the supplied options, starting
// from the package defaults.
func newConfigOptions(opts ...Option) *configOptions {
	o := defaultConfigOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

// Option configures a Configurator constructed with NewConfigurator.
type Option func(*configOptions)

// WithTestAddress overrides the URL used for the post-change connectivity
// test. The two sentinel values "test_success" and "test_fail" force the test
// to pass or fail without performing a request, which is useful in tests.
func WithTestAddress(addr string) Option {
	return func(o *configOptions) {
		if addr != "" {
			o.testAddress = addr
		}
	}
}

// WithConnectivityCheck enables or disables the post-change internet
// reachability test (and the automatic rollback that depends on it). It is
// enabled by default; pass false to skip it, for example on hosts with no
// outbound internet access.
func WithConnectivityCheck(enabled bool) Option {
	return func(o *configOptions) {
		o.skipConnectivityCheck = !enabled
	}
}

// WithSkipConnectivityCheck is a convenience option that disables the post-change
// internet reachability test and its automatic rollback. It is equivalent to
// WithConnectivityCheck(false).
func WithSkipConnectivityCheck() Option {
	return WithConnectivityCheck(false)
}

// WithConnectivityTimeout sets the timeout for the HTTP reachability test run
// after an address or gateway change. A smaller value fails faster on a
// black-holed route; a larger value tolerates slower links.
func WithConnectivityTimeout(d time.Duration) Option {
	return func(o *configOptions) {
		if d > 0 {
			o.connectivityTimeout = d
		}
	}
}

// WithPingCount sets the number of ICMP probes sent when confirming that a
// candidate address or gateway is reachable. More probes are more reliable on
// lossy links but take longer.
func WithPingCount(n int) Option {
	return func(o *configOptions) {
		if n > 0 {
			o.pingCount = n
		}
	}
}

// WithPingTimeout sets the overall timeout for a single ping run.
func WithPingTimeout(d time.Duration) Option {
	return func(o *configOptions) {
		if d > 0 {
			o.pingTimeout = d
		}
	}
}

// WithBackupRetention sets how many .bak.* copies are kept per original
// configuration file. The oldest backups beyond this number are pruned each
// time a backend saves. Pass 0 (or a negative value) to disable pruning and
// keep every backup.
func WithBackupRetention(n int) Option {
	return func(o *configOptions) {
		o.backupRetention = n
	}
}

// WithAllowPrimaryRemoval permits RemoveAddress to remove an address that is
// the primary of its family on its interface. By default removing the primary
// is refused so a caller cannot accidentally change the system's source
// address or leave a control panel without a main IP; the intended flow is to
// SetPrimaryAddress on another IP first. Enable this only when you are
// deliberately tearing down the current primary.
func WithAllowPrimaryRemoval(allowed bool) Option {
	return func(o *configOptions) {
		o.allowPrimaryRemoval = allowed
	}
}

// WithSkipPanels makes the configurator skip all control-panel backends
// (cPanel, Plesk, InterWorx) during mutating operations. When enabled,
// AddAddress, SetPrimaryAddress, and RemoveAddress do not tell the panels to
// reload, set the main IP, or release an IP; only the running system and the
// network-manager configuration files are changed. This is intended for
// maintenance paths where the panel must be left untouched, or where the panel
// is expected to be reconciled separately.
func WithSkipPanels(skip bool) Option {
	return func(o *configOptions) {
		o.skipPanels = skip
	}
}
