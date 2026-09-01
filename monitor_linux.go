//go:build linux && !android

package netstatus

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	linuxRouteGroups = 0x001 | // RTMGRP_LINK
		0x010 | // RTMGRP_IPV4_IFADDR
		0x040 | // RTMGRP_IPV4_ROUTE
		0x100 | // RTMGRP_IPV6_IFADDR
		0x400 // RTMGRP_IPV6_ROUTE
	linuxSnapshotFallbackInterval = 30 * time.Second
	linuxNetlinkAttributeTypeMask = 0x3fff
	linuxInterfaceNameSize        = 16
	linuxGetWirelessAccessPoint   = 0x8b15 // SIOCGIWAP
)

type monitor struct {
	rcvd     chan struct{}
	rcvdOnce sync.Once

	callbackMu      sync.Mutex
	mu              sync.Mutex
	last            *Status
	lastFingerprint string
	hasFingerprint  bool
	cancelled       bool
	onChange        func(Status)
}

func startMonitor(ctx context.Context) *monitor {
	m := &monitor{
		rcvd:     make(chan struct{}),
		onChange: func(Status) {},
	}

	fd, err := openLinuxRouteSocket()
	if err != nil {
		fd = -1
	}
	go m.run(ctx, fd)
	return m
}

func (m *monitor) run(ctx context.Context, fd int) {
	if fd >= 0 {
		defer syscall.Close(fd)
	}

	m.refresh()
	events := make(chan struct{}, 1)
	if fd >= 0 {
		go receiveLinuxRouteEvents(fd, events)
	}

	ticker := time.NewTicker(linuxSnapshotFallbackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.cancel()
			return
		case <-events:
			m.refresh()
		case <-ticker.C:
			// Periodic refresh is a fallback for netlink receive-buffer overflow or an unavailable
			// subscription socket. Equivalent snapshots are suppressed.
			m.refresh()
		}
	}
}

func openLinuxRouteSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: linuxRouteGroups,
	}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func receiveLinuxRouteEvents(fd int, events chan<- struct{}) {
	buffer := make([]byte, 32*1024)
	for {
		_, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ENOBUFS) {
				select {
				case events <- struct{}{}:
				default:
				}
				continue
			}
			return
		}
		select {
		case events <- struct{}{}:
		default:
		}
	}
}

func (m *monitor) refresh() {
	path, err := readLinuxPath()
	if err != nil {
		// Do not replace a known-good observation because one refresh failed. If the first refresh
		// fails, publish an unavailable status so Current still returns promptly.
		m.mu.Lock()
		hasStatus := m.last != nil
		m.mu.Unlock()
		if hasStatus {
			return
		}
		path = linuxPath{Links: map[int]linuxLink{}}
	}
	m.update(path.status(), path.fingerprint())
}

func (m *monitor) update(status Status, fingerprint string) {
	// Serialize updates while allowing Current and OnChange to be called safely from the callback.
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()

	m.mu.Lock()
	if m.cancelled {
		m.mu.Unlock()
		return
	}
	if m.last != nil && m.hasFingerprint && m.lastFingerprint == fingerprint &&
		m.last.Available == status.Available && m.last.Kind == status.Kind {
		m.mu.Unlock()
		return
	}

	if m.last == nil {
		status.Generation = 1
	} else {
		status.Generation = m.last.Generation + 1
	}
	initial := m.last == nil
	m.last = &status
	m.lastFingerprint = fingerprint
	m.hasFingerprint = true
	callback := m.onChange
	m.mu.Unlock()

	if initial {
		m.signalReceived()
		return
	}
	callback(status)
}

func (m *monitor) cancel() {
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()

	m.mu.Lock()
	m.cancelled = true
	initialPending := m.last == nil
	m.mu.Unlock()
	if initialPending {
		m.signalReceived()
	}
}

func (m *monitor) signalReceived() {
	m.rcvdOnce.Do(func() { close(m.rcvd) })
}

func (m *monitor) OnChange(callback func(Status)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = callback
}

func (m *monitor) Current(ctx context.Context) Status {
	select {
	case <-m.rcvd:
	case <-ctx.Done():
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return Status{}
	}
	return *m.last
}

func readLinuxPath() (linuxPath, error) {
	routes, err := readLinuxDefaultRoutes()
	if err != nil {
		return linuxPath{}, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return linuxPath{}, err
	}

	links := make(map[int]linuxLink, len(interfaces))
	for _, iface := range interfaces {
		addresses, _ := iface.Addrs()
		addressStrings := make([]string, 0, len(addresses))
		for _, address := range addresses {
			addressStrings = append(addressStrings, address.String())
		}
		sort.Strings(addressStrings)
		kind := linuxInterfaceKind(iface.Name, iface.Flags)
		wirelessAccessPoint := ""
		if kind == InterfaceTypeWifi {
			wirelessAccessPoint = linuxWirelessAccessPoint(iface.Name)
		}
		links[iface.Index] = linuxLink{
			Index:               iface.Index,
			Name:                iface.Name,
			Flags:               iface.Flags,
			Kind:                kind,
			WirelessAccessPoint: wirelessAccessPoint,
			Addresses:           addressStrings,
		}
	}
	return linuxPath{Routes: routes, Links: links}, nil
}

func readLinuxDefaultRoutes() ([]linuxRoute, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}

	routes := make([]linuxRoute, 0)
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWROUTE || len(message.Data) < syscall.SizeofRtMsg {
			continue
		}
		routeMessage := *(*syscall.RtMsg)(unsafe.Pointer(&message.Data[0]))
		if routeMessage.Dst_len != 0 || routeMessage.Type != syscall.RTN_UNICAST ||
			(routeMessage.Family != syscall.AF_INET && routeMessage.Family != syscall.AF_INET6) {
			continue
		}

		route := linuxRoute{Family: int(routeMessage.Family), Table: uint32(routeMessage.Table)}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			continue
		}
		for _, attribute := range attributes {
			switch int(attribute.Attr.Type & linuxNetlinkAttributeTypeMask) {
			case syscall.RTA_OIF:
				route.InterfaceIndex = int(linuxNativeUint32(attribute.Value))
			case syscall.RTA_GATEWAY:
				route.Gateway = linuxIPAddress(attribute.Value, route.Family)
			case syscall.RTA_PREFSRC:
				route.PreferredSource = linuxIPAddress(attribute.Value, route.Family)
			case syscall.RTA_PRIORITY:
				route.Metric = linuxNativeUint32(attribute.Value)
			case syscall.RTA_TABLE:
				route.Table = linuxNativeUint32(attribute.Value)
			}
		}
		if route.InterfaceIndex != 0 {
			routes = append(routes, route)
		}
	}
	return routes, nil
}

func linuxNativeUint32(value []byte) uint32 {
	if len(value) < 4 {
		return 0
	}
	return nativeEndian.Uint32(value[:4])
}

func linuxIPAddress(value []byte, family int) string {
	switch family {
	case syscall.AF_INET:
		if len(value) >= net.IPv4len {
			return net.IP(value[:net.IPv4len]).String()
		}
	case syscall.AF_INET6:
		if len(value) >= net.IPv6len {
			return net.IP(value[:net.IPv6len]).String()
		}
	}
	return ""
}

func linuxInterfaceKind(name string, flags net.Flags) InterfaceKind {
	if flags&net.FlagLoopback != 0 {
		return InterfaceTypeUnknown
	}
	if linuxPathExists("/sys/class/net/"+name+"/wireless") ||
		linuxPathExists("/sys/class/net/"+name+"/phy80211") {
		return InterfaceTypeWifi
	}
	lowerName := strings.ToLower(name)
	for _, prefix := range []string{"wwan", "wwp", "rmnet", "ccmni", "pdp", "mhi"} {
		if strings.HasPrefix(lowerName, prefix) {
			return InterfaceTypeCellular
		}
	}

	typeBytes, err := os.ReadFile("/sys/class/net/" + name + "/type")
	if err == nil && strings.TrimSpace(string(typeBytes)) == "1" {
		return InterfaceTypeWired
	}
	return InterfaceTypeUnknown
}

func linuxPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// linuxWirelessAccessPoint returns the associated BSSID through the kernel's wireless-extension
// compatibility API. Drivers that expose only route-level state simply return an empty value; the
// route, interface and source-address fingerprint remains sufficient for normal network changes.
func linuxWirelessAccessPoint(name string) string {
	if len(name) >= linuxInterfaceNameSize {
		return ""
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer syscall.Close(fd)

	request := linuxWirelessAccessPointRequest{}
	copy(request.Name[:], name)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(linuxGetWirelessAccessPoint),
		uintptr(unsafe.Pointer(&request)),
	)
	if errno != 0 {
		return ""
	}

	address := net.HardwareAddr(request.Address[:6])
	allZero := true
	for _, value := range address {
		allZero = allZero && value == 0
	}
	if allZero {
		return ""
	}
	return address.String()
}

type linuxWirelessAccessPointRequest struct {
	Name    [linuxInterfaceNameSize]byte
	Family  uint16
	Address [14]byte
}

var nativeEndian = func() binary.ByteOrder {
	value := uint16(0x0102)
	bytes := *(*[2]byte)(unsafe.Pointer(&value))
	if bytes[0] == 0x02 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()
