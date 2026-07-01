package netconfig

import (
	"context"
	"fmt"
	"time"
)

// serviceReadyPollInterval is how often waitForServiceReady re-probes. A daemon
// coming up at boot takes seconds, so probing a few times a second costs little
// and returns promptly once it arrives. It is a variable only so tests can wait
// on the loop without sleeping for real.
var serviceReadyPollInterval = 250 * time.Millisecond

// readyProbe reports whether a service is ready to be configured. An error is a
// probe that could not reach the service, which during boot is indistinguishable
// from a service that has not started yet; it is therefore not fatal on its own
// and is only surfaced if the wait runs out.
type readyProbe func() (bool, error)

// waitForServiceReady blocks until probe reports the named service ready, the
// timeout elapses, or ctx is cancelled.
//
// Some backends are configured through a running daemon rather than a file, so
// a configurator constructed before that daemon is up would hold a handle that
// reports nothing and accepts no changes. This program can be started early
// enough in boot to lose that race — from a unit ordered alongside the daemon
// rather than after it — which is what the wait is for.
//
// A timeout of zero or less does not wait: probe runs once and its result is
// reported, so a caller already ordered after the daemon fails fast instead of
// blocking. A service that is already up returns on the first probe and pays no
// delay either way.
func waitForServiceReady(ctx context.Context, name string, timeout time.Duration, probe readyProbe) error {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ticker := time.NewTicker(serviceReadyPollInterval)
	defer ticker.Stop()

	waited := false
	for {
		ready, probeErr := probe()
		if ready {
			if waited {
				logger.Printf("%s: became ready", name)
			}
			return nil
		}

		// Not waiting: report why the single probe said no.
		if timeout <= 0 {
			if probeErr != nil {
				return fmt.Errorf("%s is not ready: %w", name, probeErr)
			}
			return fmt.Errorf("%s is not ready", name)
		}

		if !waited {
			waited = true
			logger.Printf("%s: waiting up to %s for the service to become ready", name, timeout)
		}

		select {
		case <-ctx.Done():
			// The last probe error explains the wait better than "deadline
			// exceeded" does, so prefer it when there was one.
			if probeErr != nil {
				return fmt.Errorf("timed out waiting for %s: %w", name, probeErr)
			}
			return fmt.Errorf("timed out waiting for %s: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}
