//go:build darwin && cgo

package netstatus

import (
	"context"
	"sync"
	"testing"
	"time"
)

func newTestMonitor() *monitor {
	return &monitor{
		rcvd:     make(chan struct{}),
		onChange: func(Status) {},
	}
}

func TestSignalReceivedCanBeCalledConcurrently(t *testing.T) {
	m := newTestMonitor()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.signalReceived()
		}()
	}
	wg.Wait()

	select {
	case <-m.rcvd:
	default:
		t.Fatal("received channel was not closed")
	}
}

func TestOnChangeCanAccessMonitor(t *testing.T) {
	m := newTestMonitor()
	called := make(chan struct{})
	m.OnChange(func(Status) {
		m.Current(context.Background())
		m.OnChange(func(Status) {})
		close(called)
	})

	done := make(chan struct{})
	go func() {
		m.update(Status{Available: false}, 1)
		m.update(Status{Available: true, Kind: InterfaceTypeWifi}, 2)
		close(done)
	}()

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("change callback deadlocked while accessing the monitor")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("status updates did not finish")
	}
}

func TestPathGenerationAdvancesForDifferentFingerprintWithEquivalentStatus(t *testing.T) {
	m := newTestMonitor()
	wifi := Status{Available: true, Kind: InterfaceTypeWifi}
	m.update(wifi, 1)

	if got := m.Current(context.Background()); got.Generation != 1 {
		t.Fatalf("initial generation: got %d, want 1", got.Generation)
	}

	changed := make(chan Status, 1)
	m.OnChange(func(status Status) { changed <- status })
	m.update(wifi, 2)

	select {
	case got := <-changed:
		if !got.Available || got.Kind != InterfaceTypeWifi {
			t.Fatalf("coarse status changed: got %+v", got)
		}
		if got.Generation != 2 {
			t.Fatalf("updated generation: got %d, want 2", got.Generation)
		}
	case <-time.After(time.Second):
		t.Fatal("equivalent Wi-Fi path update was suppressed")
	}

	if got := m.Current(context.Background()); got.Generation != 2 {
		t.Fatalf("current generation: got %d, want 2", got.Generation)
	}
}

func TestEquivalentPathFingerprintIsSuppressed(t *testing.T) {
	m := newTestMonitor()
	wifi := Status{Available: true, Kind: InterfaceTypeWifi}
	m.update(wifi, 1)

	changed := make(chan Status, 1)
	m.OnChange(func(status Status) { changed <- status })
	m.update(wifi, 1)

	select {
	case got := <-changed:
		t.Fatalf("equivalent path fingerprint triggered change: %+v", got)
	default:
	}

	if got := m.Current(context.Background()); got.Generation != 1 {
		t.Fatalf("current generation: got %d, want 1", got.Generation)
	}
}

func TestCoarseStatusChangeIsPublishedForEquivalentPathFingerprint(t *testing.T) {
	m := newTestMonitor()
	m.update(Status{Available: false}, 1)

	changed := make(chan Status, 1)
	m.OnChange(func(status Status) { changed <- status })
	m.update(Status{Available: true, Kind: InterfaceTypeWifi}, 1)

	select {
	case got := <-changed:
		if got.Generation != 2 || !got.Available || got.Kind != InterfaceTypeWifi {
			t.Fatalf("updated status: got %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("coarse status change was suppressed")
	}
}

func TestUpdateAfterCancelIsIgnored(t *testing.T) {
	m := newTestMonitor()
	m.update(Status{Available: true, Kind: InterfaceTypeWifi}, 1)
	m.cancel()
	m.update(Status{Available: false}, 2)

	if got := m.Current(context.Background()); got.Generation != 1 || !got.Available {
		t.Fatalf("status changed after cancel: %+v", got)
	}
}
