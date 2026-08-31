//go:build windows && cgo

package netstatus

import (
	"context"
	"testing"
	"time"
)

func TestImmediateCancellationReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := StartMonitor(ctx)
	done := make(chan struct{})
	go func() {
		m.Current(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("monitor did not stop after immediate cancellation")
	}
}

func TestOnChangeCanAccessMonitor(t *testing.T) {
	m := &monitor{
		rcvd:     make(chan struct{}),
		onChange: func(Status) {},
	}
	called := make(chan struct{})
	m.OnChange(func(Status) {
		m.Current(context.Background())
		m.OnChange(func(Status) {})
		close(called)
	})

	done := make(chan struct{})
	go func() {
		m.rawCallback(false)
		m.rawCallback(true)
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

func TestPathGenerationAdvancesForEquivalentStatus(t *testing.T) {
	m := &monitor{
		rcvd:     make(chan struct{}),
		onChange: func(Status) {},
	}
	m.rawCallback(true)

	if got := m.Current(context.Background()); got.Generation != 1 {
		t.Fatalf("initial generation: got %d, want 1", got.Generation)
	}

	changed := make(chan Status, 1)
	m.OnChange(func(status Status) { changed <- status })
	m.rawCallback(true)

	select {
	case got := <-changed:
		if !got.Available || got.Kind != InterfaceTypeUnknown {
			t.Fatalf("coarse status changed: got %+v", got)
		}
		if got.Generation != 2 {
			t.Fatalf("updated generation: got %d, want 2", got.Generation)
		}
	case <-time.After(time.Second):
		t.Fatal("equivalent connectivity update was suppressed")
	}

	if got := m.Current(context.Background()); got.Generation != 2 {
		t.Fatalf("current generation: got %d, want 2", got.Generation)
	}
}
