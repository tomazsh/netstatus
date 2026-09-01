//go:build linux && !android

package netstatus

import (
	"net"
	"testing"
)

func TestLinuxPathFingerprintIsOrderIndependent(t *testing.T) {
	first := linuxPath{
		Routes: []linuxRoute{
			{Family: 10, InterfaceIndex: 3, Gateway: "fe80::1", Metric: 100, Table: 254},
			{Family: 2, InterfaceIndex: 3, Gateway: "192.168.1.1", Metric: 100, Table: 254},
		},
		Links: map[int]linuxLink{
			3: {
				Index:     3,
				Name:      "wlan0",
				Flags:     net.FlagUp,
				Kind:      InterfaceTypeWifi,
				Addresses: []string{"2001:db8::2/64", "192.168.1.20/24"},
			},
		},
	}
	second := linuxPath{
		Routes: []linuxRoute{first.Routes[1], first.Routes[0]},
		Links: map[int]linuxLink{
			3: {
				Index:     3,
				Name:      "wlan0",
				Flags:     net.FlagUp,
				Kind:      InterfaceTypeWifi,
				Addresses: []string{"192.168.1.20/24", "2001:db8::2/64"},
			},
		},
	}

	if first.fingerprint() != second.fingerprint() {
		t.Fatalf("equivalent Linux paths produced different fingerprints:\n%s\n%s", first.fingerprint(), second.fingerprint())
	}
}

func TestLinuxWifiToWifiPathChangesFingerprintWithoutChangingStatus(t *testing.T) {
	first := linuxWifiPath("192.168.1.1", "192.168.1.20/24")
	second := linuxWifiPath("192.168.50.1", "192.168.50.20/24")

	if got := first.status(); !got.Available || got.Kind != InterfaceTypeWifi {
		t.Fatalf("first status: got %+v", got)
	}
	if got := second.status(); !got.Available || got.Kind != InterfaceTypeWifi {
		t.Fatalf("second status: got %+v", got)
	}
	if first.fingerprint() == second.fingerprint() {
		t.Fatal("different Wi-Fi routes produced the same fingerprint")
	}
}

func TestLinuxWifiAccessPointChangeAdvancesFingerprintOnSameRoute(t *testing.T) {
	first := linuxWifiPath("192.168.1.1", "192.168.1.20/24")
	firstLink := first.Links[3]
	firstLink.WirelessAccessPoint = "00:11:22:33:44:55"
	first.Links[3] = firstLink

	second := linuxWifiPath("192.168.1.1", "192.168.1.20/24")
	secondLink := second.Links[3]
	secondLink.WirelessAccessPoint = "00:11:22:33:44:66"
	second.Links[3] = secondLink

	if first.status() != second.status() {
		t.Fatalf("access-point transition changed coarse status: %+v, %+v", first.status(), second.status())
	}
	if first.fingerprint() == second.fingerprint() {
		t.Fatal("different Wi-Fi access points produced the same fingerprint")
	}
}

func TestLinuxPathStatusRequiresAnUpDefaultRoute(t *testing.T) {
	path := linuxWifiPath("192.168.1.1", "192.168.1.20/24")
	link := path.Links[3]
	link.Flags = 0
	path.Links[3] = link

	if got := path.status(); got.Available || got.Kind != InterfaceTypeUnknown {
		t.Fatalf("down route reported usable: %+v", got)
	}
}

func TestLinuxPathUsesLowestMetricRouteKind(t *testing.T) {
	path := linuxPath{
		Routes: []linuxRoute{
			{Family: 2, InterfaceIndex: 2, Gateway: "10.0.0.1", Metric: 200, Table: 254},
			{Family: 2, InterfaceIndex: 3, Gateway: "192.168.1.1", Metric: 100, Table: 254},
		},
		Links: map[int]linuxLink{
			2: {Index: 2, Name: "eth0", Flags: net.FlagUp, Kind: InterfaceTypeWired},
			3: {Index: 3, Name: "wlan0", Flags: net.FlagUp, Kind: InterfaceTypeWifi},
		},
	}

	if got := path.status(); !got.Available || got.Kind != InterfaceTypeWifi {
		t.Fatalf("status did not use lowest-metric route: %+v", got)
	}
}

func linuxWifiPath(gateway, address string) linuxPath {
	return linuxPath{
		Routes: []linuxRoute{{
			Family:         2,
			InterfaceIndex: 3,
			Gateway:        gateway,
			Metric:         100,
			Table:          254,
		}},
		Links: map[int]linuxLink{
			3: {
				Index:     3,
				Name:      "wlan0",
				Flags:     net.FlagUp,
				Kind:      InterfaceTypeWifi,
				Addresses: []string{address},
			},
		},
	}
}
