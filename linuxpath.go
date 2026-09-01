//go:build linux && !android

package netstatus

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// linuxRoute and linuxLink contain only connection-relevant public state. Keeping the snapshot
// independent of raw netlink messages makes duplicate kernel notifications compare equal.
type linuxRoute struct {
	Family          int
	InterfaceIndex  int
	Gateway         string
	PreferredSource string
	Metric          uint32
	Table           uint32
}

type linuxLink struct {
	Index               int
	Name                string
	Flags               net.Flags
	Kind                InterfaceKind
	WirelessAccessPoint string
	Addresses           []string
}

type linuxPath struct {
	Routes []linuxRoute
	Links  map[int]linuxLink
}

func (p linuxPath) status() Status {
	usable := p.usableRoutes()
	if len(usable) == 0 {
		return Status{Available: false, Kind: InterfaceTypeUnknown}
	}

	// The lowest-metric usable default route is the best approximation of the route selected for
	// a new internet connection. The complete set is still included in the fingerprint below.
	best := usable[0]
	for _, route := range usable[1:] {
		if route.Metric < best.Metric {
			best = route
		}
	}
	return Status{Available: true, Kind: p.Links[best.InterfaceIndex].Kind}
}

func (p linuxPath) fingerprint() string {
	routes := append([]linuxRoute(nil), p.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		return linuxRouteKey(routes[i]) < linuxRouteKey(routes[j])
	})

	var fingerprint strings.Builder
	for _, route := range routes {
		fmt.Fprintf(&fingerprint, "route:%s\n", linuxRouteKey(route))
		link, ok := p.Links[route.InterfaceIndex]
		if !ok {
			continue
		}
		addresses := append([]string(nil), link.Addresses...)
		sort.Strings(addresses)
		fmt.Fprintf(
			&fingerprint,
			"link:%d|%s|%t|%s|%s|%s\n",
			link.Index,
			link.Name,
			link.Flags&net.FlagUp != 0,
			link.Kind,
			link.WirelessAccessPoint,
			strings.Join(addresses, ","),
		)
	}
	return fingerprint.String()
}

func (p linuxPath) usableRoutes() []linuxRoute {
	usable := make([]linuxRoute, 0, len(p.Routes))
	for _, route := range p.Routes {
		link, ok := p.Links[route.InterfaceIndex]
		if ok && link.Flags&net.FlagUp != 0 {
			usable = append(usable, route)
		}
	}
	return usable
}

func linuxRouteKey(route linuxRoute) string {
	return fmt.Sprintf(
		"%d|%d|%s|%s|%010d|%010d",
		route.Family,
		route.InterfaceIndex,
		route.Gateway,
		route.PreferredSource,
		route.Metric,
		route.Table,
	)
}
