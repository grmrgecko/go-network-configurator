package netconfig

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastPolling shrinks the readiness poll interval for the duration of a test,
// so the wait loop can be exercised without sleeping for real.
func fastPolling(t *testing.T) {
	t.Helper()
	original := serviceReadyPollInterval
	serviceReadyPollInterval = time.Millisecond
	t.Cleanup(func() { serviceReadyPollInterval = original })
}

// countingProbe reports ready only from the nth call onwards, and records how
// many times it was asked.
func countingProbe(readyOn int, err error) (readyProbe, *int) {
	calls := 0
	probe := func() (bool, error) {
		calls++
		if readyOn > 0 && calls >= readyOn {
			return true, nil
		}
		return false, err
	}
	return probe, &calls
}

func TestWaitForServiceReady(t *testing.T) {
	t.Run("a service already up returns on the first probe", func(t *testing.T) {
		fastPolling(t)
		probe, calls := countingProbe(1, nil)

		err := waitForServiceReady(context.Background(), "svc", time.Minute, probe)
		require.NoError(t, err)
		assert.Equal(t, 1, *calls, "a ready service must not be polled twice")
	})

	t.Run("waits until the service arrives", func(t *testing.T) {
		fastPolling(t)
		probe, calls := countingProbe(4, errors.New("no bus yet"))

		err := waitForServiceReady(context.Background(), "svc", time.Minute, probe)
		require.NoError(t, err)
		assert.Equal(t, 4, *calls)
	})

	t.Run("a probe error while booting is not fatal", func(t *testing.T) {
		fastPolling(t)
		// The first probes fail with the error a host that has not started
		// dbus-daemon yet would give; the service then arrives.
		probe, _ := countingProbe(3, errors.New("dial unix /run/dbus: no such file"))

		assert.NoError(t, waitForServiceReady(context.Background(), "svc", time.Minute, probe))
	})

	t.Run("times out and reports the last probe error", func(t *testing.T) {
		fastPolling(t)
		probeErr := errors.New("name has no owner")
		probe, calls := countingProbe(0, probeErr)

		err := waitForServiceReady(context.Background(), "NetworkManager", 20*time.Millisecond, probe)
		require.Error(t, err)
		assert.ErrorIs(t, err, probeErr, "the probe error explains the wait better than a deadline does")
		assert.ErrorContains(t, err, "timed out waiting for NetworkManager")
		assert.Greater(t, *calls, 1, "the probe must be retried before giving up")
	})

	t.Run("times out and reports the deadline when the probe never errored", func(t *testing.T) {
		fastPolling(t)
		probe, _ := countingProbe(0, nil)

		err := waitForServiceReady(context.Background(), "svc", 20*time.Millisecond, probe)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("a cancelled context aborts the wait", func(t *testing.T) {
		fastPolling(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		probe, _ := countingProbe(0, nil)

		err := waitForServiceReady(ctx, "svc", time.Minute, probe)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("zero timeout probes once and does not wait", func(t *testing.T) {
		probe, calls := countingProbe(0, nil)

		start := time.Now()
		err := waitForServiceReady(context.Background(), "svc", 0, probe)
		require.Error(t, err)
		assert.ErrorContains(t, err, "svc is not ready")
		assert.Equal(t, 1, *calls, "a zero timeout must not retry")
		assert.Less(t, time.Since(start), serviceReadyPollInterval, "a zero timeout must not sleep")
	})

	t.Run("zero timeout surfaces the probe error", func(t *testing.T) {
		probeErr := errors.New("name has no owner")
		probe, _ := countingProbe(0, probeErr)

		err := waitForServiceReady(context.Background(), "svc", 0, probe)
		require.Error(t, err)
		assert.ErrorIs(t, err, probeErr)
	})

	t.Run("zero timeout still succeeds when the service is up", func(t *testing.T) {
		probe, calls := countingProbe(1, nil)

		assert.NoError(t, waitForServiceReady(context.Background(), "svc", 0, probe))
		assert.Equal(t, 1, *calls)
	})
}
