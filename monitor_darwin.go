//go:build cgo

package netstatus

/*
#cgo CFLAGS: -x objective-c -Wno-incompatible-pointer-types
#cgo LDFLAGS: -framework Foundation -framework Network
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <stdint.h>
#include <string.h>

extern void invoke_callback(uintptr_t hnd, nw_path_t path);

static uint64_t fingerprint_bytes(uint64_t hash, const void *bytes, size_t length) {
	const uint8_t *cursor = bytes;
	for (size_t i = 0; i < length; i++) {
		hash ^= cursor[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}

static uint64_t fingerprint_uint64(uint64_t hash, uint64_t value) {
	return fingerprint_bytes(hash, &value, sizeof(value));
}

static uint64_t fingerprint_string(uint64_t hash, const char *value) {
	if (value == NULL) {
		return fingerprint_uint64(hash, UINT64_MAX);
	}
	size_t length = strlen(value);
	hash = fingerprint_uint64(hash, length);
	return fingerprint_bytes(hash, value, length);
}

static uint64_t fingerprint_endpoint(uint64_t hash, nw_endpoint_t endpoint) {
	if (endpoint == NULL) {
		return fingerprint_uint64(hash, UINT64_MAX);
	}
	hash = fingerprint_uint64(hash, nw_endpoint_get_type(endpoint));
	hash = fingerprint_string(hash, nw_endpoint_get_hostname(endpoint));
	return fingerprint_uint64(hash, nw_endpoint_get_port(endpoint));
}

// Fingerprint the public path properties that determine how connections are
// routed. NWPath's native equality also includes transient internal state on
// iOS, which can change after opening a connection without changing its route.
static uint64_t path_fingerprint(nw_path_t path) {
	uint64_t hash = 14695981039346656037ULL;
	hash = fingerprint_uint64(hash, nw_path_get_status(path));
	hash = fingerprint_uint64(hash, nw_path_is_expensive(path));
	hash = fingerprint_uint64(hash, nw_path_is_constrained(path));
	hash = fingerprint_uint64(hash, nw_path_has_ipv4(path));
	hash = fingerprint_uint64(hash, nw_path_has_ipv6(path));
	hash = fingerprint_uint64(hash, nw_path_has_dns(path));

	__block uint64_t interface_hash = 14695981039346656037ULL;
	__block uint64_t interface_count = 0;
	nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
		nw_interface_type_t type = nw_interface_get_type(interface);
		if (!nw_path_uses_interface_type(path, type)) {
			return true;
		}
		interface_count++;
		interface_hash = fingerprint_uint64(interface_hash, type);
		interface_hash = fingerprint_uint64(interface_hash, nw_interface_get_index(interface));
		interface_hash = fingerprint_string(interface_hash, nw_interface_get_name(interface));
		return true;
	});
	hash = fingerprint_uint64(hash, interface_count);
	hash = fingerprint_uint64(hash, interface_hash);

	__block uint64_t gateway_hash = 14695981039346656037ULL;
	__block uint64_t gateway_count = 0;
	nw_path_enumerate_gateways(path, ^bool(nw_endpoint_t gateway) {
		gateway_count++;
		gateway_hash = fingerprint_endpoint(gateway_hash, gateway);
		return true;
	});
	hash = fingerprint_uint64(hash, gateway_count);
	hash = fingerprint_uint64(hash, gateway_hash);

	nw_endpoint_t local_endpoint = nw_path_copy_effective_local_endpoint(path);
	hash = fingerprint_endpoint(hash, local_endpoint);
	if (local_endpoint != NULL) {
		nw_release(local_endpoint);
	}
	return hash;
}
static void set_update_handler(nw_path_monitor_t monitor, uintptr_t cb_hnd) {
	nw_path_monitor_set_update_handler(monitor, ^(nw_path_t path) {
		// The docs say retain/release are needed, though other implementations don't do so?
		nw_retain(path);
		invoke_callback(cb_hnd, path);
		nw_release(path);
	});
}

extern void invoke_cancel(uintptr_t hnd);
static void set_cancel_handler(nw_path_monitor_t monitor, uintptr_t cb_hnd) {
	// Capture the monitor as an integer so the block does not retain it and
	// create a cycle. The reference returned by nw_path_monitor_create is
	// released once native cancellation has completed.
	uintptr_t monitor_hnd = (uintptr_t)monitor;
	nw_path_monitor_set_cancel_handler(monitor, ^{
		invoke_cancel(cb_hnd);
		nw_release((nw_path_monitor_t)monitor_hnd);
	});
}
*/
import "C"
import (
	"context"
	"fmt"
	"runtime/cgo"
	"sync"
)

type monitor struct {
	rcvd     chan struct{}
	rcvdOnce sync.Once

	callbackMu      sync.Mutex
	lastFingerprint pathFingerprint
	hasFingerprint  bool
	cancelled       bool
	mu              sync.Mutex
	last            *Status
	onChange        func(Status)
}

type pathFingerprint uint64

func startMonitor(ctx context.Context) *monitor {
	mon := C.nw_path_monitor_create()
	if mon == nil {
		// This should never happen®. The docs say this will only fail due to bad arguments.
		panic(fmt.Sprintf("nw_path_monitor_create: %v", mon))
	}
	m := &monitor{
		rcvd:     make(chan struct{}),
		onChange: func(Status) {},
	}
	// The initial callback won't be fired if the queue isn't set.
	// Using the main queue results in deadlock--don't do it!
	C.nw_path_monitor_set_queue(mon, C.dispatch_get_global_queue(C.QOS_CLASS_DEFAULT, 0))

	// Use a cgo.Handle to give C an opaque, unique callback ID. Callbacks resolve
	// the monitor through callbacks rather than Handle.Value: the cancel handler
	// may delete the handle while an update is already queued on the dispatch
	// queue, and using a deleted handle panics.
	cbHnd := cgo.NewHandle(m)
	callbacksMu.Lock()
	callbacks[C.uintptr_t(cbHnd)] = m
	callbacksMu.Unlock()
	C.set_update_handler(mon, C.uintptr_t(cbHnd))
	C.set_cancel_handler(mon, C.uintptr_t(cbHnd))

	// The callback should get fired immediately with the current state, as per the docs
	// in path_monitor.h for nw_path_monitor_set_update_handler
	C.nw_path_monitor_start(mon)

	go func() {
		<-ctx.Done()
		C.nw_path_monitor_cancel(mon)

		m.mu.Lock()
		defer m.mu.Unlock()
		if m.last == nil {
			m.signalReceived()
		}
	}()

	return m
}

func (m *monitor) rawCallback(path C.nw_path_t) {
	status := makeStatus(path)
	fingerprint := pathFingerprint(C.path_fingerprint(path))
	m.update(status, fingerprint)
}

func (m *monitor) update(status Status, fingerprint pathFingerprint) {
	// Serialize native updates while allowing Current and OnChange to be called
	// safely from the user callback.
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()

	if m.cancelled {
		return
	}
	m.updateLocked(status, fingerprint)
}

// updateLocked applies a path update and reports whether it was published.
// callbackMu must be held by the caller.
func (m *monitor) updateLocked(status Status, fingerprint pathFingerprint) bool {
	m.mu.Lock()
	if m.last != nil && m.hasFingerprint && m.lastFingerprint == fingerprint &&
		m.last.Available == status.Available && m.last.Kind == status.Kind {
		m.mu.Unlock()
		return false
	}

	if m.last == nil {
		status.Generation = 1
	} else {
		status.Generation = m.last.Generation + 1
	}

	var changed bool
	if m.last == nil {
		m.signalReceived()
	} else if *m.last != status {
		changed = true
	}

	m.last = &status
	m.lastFingerprint = fingerprint
	m.hasFingerprint = true
	cb := m.onChange
	m.mu.Unlock()

	// Only fire callback if the status actually changed
	if changed {
		cb(status)
	}
	return true
}

func (m *monitor) cancel() {
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()

	if m.cancelled {
		return
	}
	m.cancelled = true
}

func (m *monitor) signalReceived() {
	m.rcvdOnce.Do(func() { close(m.rcvd) })
}

func (m *monitor) OnChange(cb func(Status)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = cb
}

func (m *monitor) Current(ctx context.Context) Status {
	// Wait until the callback is triggered. This should happen near-instantaneously.
	// Ctx to allow cancellation in case it doesn't.
	select {
	case <-m.rcvd:
	case <-ctx.Done():
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// This would happen if StartMonitor was immediately followed with Close before any values were received
	if m.last == nil {
		return Status{}
	}

	return *m.last
}

func makeStatus(path C.nw_path_t) Status {
	kind := InterfaceTypeUnknown
	if bool(C.nw_path_is_expensive(path)) {
		// Tethering: interface type may be Wifi or Wired, but is ultimately Cellular.
		kind = InterfaceTypeCellular
	} else if bool(C.nw_path_uses_interface_type(path, C.nw_interface_type_cellular)) {
		kind = InterfaceTypeCellular
	} else if bool(C.nw_path_uses_interface_type(path, C.nw_interface_type_wifi)) {
		kind = InterfaceTypeWifi
	} else if bool(C.nw_path_uses_interface_type(path, C.nw_interface_type_wired)) {
		kind = InterfaceTypeWired
	}
	s := C.nw_path_get_status(path)
	return Status{
		Available: s == C.nw_path_status_satisfied || s == C.nw_path_status_satisfiable,
		Kind:      kind,
	}
}

var callbacksMu sync.Mutex
var callbacks = map[C.uintptr_t]*monitor{}

// Invokes the callback identified by hnd. Used to provide a C-exported function that can safely
// ignore an update delivered after cancellation.
//
//export invoke_callback
func invoke_callback(hnd C.uintptr_t, path C.nw_path_t) {
	callbacksMu.Lock()
	m := callbacks[hnd]
	callbacksMu.Unlock()

	if m != nil {
		m.rawCallback(path)
	}
}

//export invoke_cancel
func invoke_cancel(hnd C.uintptr_t) {
	callbacksMu.Lock()
	m, ok := callbacks[hnd]
	if ok {
		delete(callbacks, hnd)
	}
	callbacksMu.Unlock()

	// Guard against an unexpected duplicate native cancellation callback.
	if ok {
		m.cancel()
		cgo.Handle(hnd).Delete()
	}
}
