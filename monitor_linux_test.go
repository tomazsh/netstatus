//go:build linux && !android

package netstatus

import (
	"context"
	"sync"
	"testing"
	"time"
)

func newLinuxTestMonitor() *monitor {
	return &monitor{
		rcvd:     make(chan struct{}),
		onChange: func(Status) {},
	}
}

func TestLinuxSignalReceivedCanBeCalledConcurrently(t *testing.T) {
	m := newLinuxTestMonitor()

	var waitGroup sync.WaitGroup
	for i := 0; i < 100; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			m.signalReceived()
		}()
	}
	waitGroup.Wait()

	select {
	case <-m.rcvd:
	default:
		t.Fatal("received channel was not closed")
	}
}

func TestLinuxOnChangeCanAccessMonitor(t *testing.T) {
	m := newLinuxTestMonitor()
	called := make(chan struct{})
	m.OnChange(func(Status) {
		m.Current(context.Background())
		m.OnChange(func(Status) {})
		close(called)
	})

	m.update(Status{Available: false}, "unavailable")
	m.update(Status{Available: true, Kind: InterfaceTypeWifi}, "wifi-a")

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("change callback deadlocked while accessing the monitor")
	}
}

func TestLinuxPathGenerationAdvancesForEquivalentCoarseStatus(t *testing.T) {
	m := newLinuxTestMonitor()
	wifi := Status{Available: true, Kind: InterfaceTypeWifi}
	m.update(wifi, "wifi-a")

	changed := make(chan Status, 1)
	m.OnChange(func(status Status) { changed <- status })
	m.update(wifi, "wifi-b")

	select {
	case got := <-changed:
		if got.Generation != 2 || !got.Available || got.Kind != InterfaceTypeWifi {
			t.Fatalf("updated status: got %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("equivalent Wi-Fi path update was suppressed")
	}
}

func TestLinuxEquivalentPathIsSuppressed(t *testing.T) {
	m := newLinuxTestMonitor()
	wifi := Status{Available: true, Kind: InterfaceTypeWifi}
	m.update(wifi, "wifi-a")

	changed := make(chan Status, 1)
	m.OnChange(func(status Status) { changed <- status })
	m.update(wifi, "wifi-a")

	select {
	case got := <-changed:
		t.Fatalf("equivalent path triggered change: %+v", got)
	default:
	}
	if got := m.Current(context.Background()); got.Generation != 1 {
		t.Fatalf("generation: got %d, want 1", got.Generation)
	}
}

func TestLinuxUpdateAfterCancelIsIgnored(t *testing.T) {
	m := newLinuxTestMonitor()
	m.update(Status{Available: true, Kind: InterfaceTypeWifi}, "wifi-a")
	m.cancel()
	m.update(Status{Available: false}, "unavailable")

	if got := m.Current(context.Background()); got.Generation != 1 || !got.Available {
		t.Fatalf("status changed after cancel: %+v", got)
	}
}
