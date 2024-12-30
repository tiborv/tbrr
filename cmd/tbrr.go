package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("current capabilities", slog.Any("capabilities", cap.GetProc()))
	caps := cap.NewSet()
	if err := caps.SetFlag(cap.Effective, true, cap.NET_RAW, cap.NET_ADMIN); err != nil {
		slog.Error("failed to set capabilities", slog.Any("error", err))
		os.Exit(1)
	}

	var routerIPs []string
	if len(os.Args) > 1 {
		routerIPs = os.Args[1:]
		slog.Info("parsed router IPs", slog.Any("routerIPs", routerIPs))
	}

	if len(routerIPs) == 0 {
		slog.Error("invalid usage", slog.String("usage", os.Args[0]+" <router-ip1> [router-ip2] ..."))
		os.Exit(1)
	}

	var (
		ifi *net.Interface
		err error
	)

	if os.Getenv("INTERFACE_NAME") != "" {
		if ifi, err = net.InterfaceByName(os.Getenv("INTERFACE_NAME")); err != nil {
			slog.Error("failed to find interface by name", slog.Any("error", err))
			os.Exit(1)
		}
	}

	if ifi == nil && os.Getenv("INTERFACE_IPS") != "" {
		ips := strings.Split(os.Getenv("INTERFACE_IPS"), ",")
		for _, ip := range ips {
			if ifi, err = findInterfaceByIPv6(ip); err == nil {
				break
			}
		}
	}

	if ifi == nil {
		slog.Error("no network interface found")
		os.Exit(1)
	}

	slog.Info("using interface", slog.String("interface", ifi.Name))

	conn, _, err := ndp.Listen(ifi, ndp.Addr(string(ndp.LinkLocal)))
	if err != nil {
		slog.Error("failed to set up NDP listener", slog.Any("error", err))
		os.Exit(1)
	}
	defer conn.Close()

	rsMsg := &ndp.RouterSolicitation{
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      ifi.HardwareAddr,
			},
		},
	}

	ips := []netip.Addr{}
	for _, ipStr := range routerIPs {
		ips = append(ips, netip.MustParseAddr(ipStr))
	}

	syncInterval := "60s"
	if os.Getenv("SYNC_INTERVAL") != "" {
		syncInterval = os.Getenv("SYNC_INTERVAL")
	}
	syncIntervalDuration, err := time.ParseDuration(syncInterval)
	if err != nil {
		slog.Error("failed to parse sync interval", slog.String("syncInterval", syncInterval), slog.Any("error", err))
		os.Exit(1)
	}

	receiveTimeout := "5s"
	if os.Getenv("RECEIVE_TIMEOUT") != "" {
		receiveTimeout = os.Getenv("RECEIVE_TIMEOUT")
	}
	receiveTimeoutDuration, err := time.ParseDuration(receiveTimeout)
	if err != nil {
		slog.Error("failed to parse receive timeout", slog.String("receiveTimeout", receiveTimeout), slog.Any("error", err))
		os.Exit(1)
	}

	for {
		slog.Info("starting sync")
		for _, ip := range ips {
			ctx, cancel := context.WithTimeout(context.Background(), receiveTimeoutDuration)
			routeInfoChan := make(chan []*ndp.RouteInformation)

			go receiveRA(ctx, conn, ip, routeInfoChan)
			go sendRS(conn, rsMsg, ip)

			select {
			case <-ctx.Done():
				slog.Warn("timed out waiting for RA", slog.String("router_ip", ip.String()))
			case routeInfo, ok := <-routeInfoChan:
				if !ok {
					slog.Warn("no RA received", slog.String("router_ip", ip.String()))
					break
				}
				for _, rinfo := range routeInfo {
					slog.Info("adding route",
						slog.String("prefix", rinfo.Prefix.String()),
						slog.Int("prefix_length", int(rinfo.PrefixLength)),
						slog.String("via_router", ip.String()),
						slog.String("interface", ifi.Name))
					addRoute(fmt.Sprintf("%s/%d", rinfo.Prefix, rinfo.PrefixLength), ip.String(), ifi.Name)
				}
			}
			cancel()
		}
		slog.Info("sync completed")
		time.Sleep(syncIntervalDuration)
	}
}

// Send a router solicitation
func sendRS(conn *ndp.Conn, msg *ndp.RouterSolicitation, dst netip.Addr) {
	if err := conn.WriteTo(msg, nil, dst); err != nil {
		slog.Error("failed to send router solicitation",
			slog.String("destination", dst.String()),
			slog.Any("error", err))
		return
	}
	slog.Info("sent router solicitation", slog.String("destination", dst.String()))
}

// Receive a router advertisement and process the route information
func receiveRA(ctx context.Context, conn *ndp.Conn, dst netip.Addr, routeInfoChan chan<- []*ndp.RouteInformation) {
	defer close(routeInfoChan) // Ensure channel is closed when exiting the function

	for {
		select {
		case <-ctx.Done(): // Handle timeout or cancellation
			slog.Warn("receiveRA timed out", slog.String("destination", dst.String()))
			return
		default:
			respMsg, _, respAddr, err := conn.ReadFrom()
			if err != nil {
				slog.Error("Failed to read from connection", slog.Any("error", err))
				return
			}
			if respAddr.As16() != dst.As16() {
				slog.Info("skipping message from unexpected source",
					slog.String("received_from", respAddr.String()),
					slog.String("expected", dst.String()))
				continue
			}
			ra, ok := respMsg.(*ndp.RouterAdvertisement)
			if !ok {
				slog.Info("skipping non-RA message", slog.String("message_type", respMsg.Type().String()))
				continue
			}

			routeInfo := []*ndp.RouteInformation{}
			for _, o := range ra.Options {
				if rinfo, ok := o.(*ndp.RouteInformation); ok {
					routeInfo = append(routeInfo, rinfo)
				}
			}

			slog.Info("router advertisement received", slog.String("destination", dst.String()), slog.Int("routes_found", len(routeInfo)))
			routeInfoChan <- routeInfo
			return
		}
	}
}

func addRoute(prefix, gateway, ifaceName string) {
	_, dst, err := net.ParseCIDR(prefix)
	if err != nil {
		slog.Warn("invalid prefix", slog.String("prefix", prefix), slog.Any("error", err))
		return
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		slog.Warn("invalid gateway IP", slog.String("gateway", gateway))
		return
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		slog.Error("failed to find network interface", slog.String("interface", ifaceName), slog.Any("error", err))
		return
	}

	if commit := os.Getenv("COMMIT"); commit == "" {
		slog.Info("COMMIT != true; would have added route",
			slog.String("prefix", prefix),
			slog.String("gateway", gateway),
			slog.String("interface", ifaceName))
		return
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}

	// Try to replace the route
	if err = netlink.RouteReplace(route); err == nil {
		slog.Info("route replaced",
			slog.String("prefix", prefix),
			slog.String("gateway", gateway),
			slog.String("interface", ifaceName))
		return
	}

	slog.Warn("failed to replace route, attempting to add route",
		slog.String("prefix", prefix),
		slog.String("gateway", gateway),
		slog.String("interface", ifaceName),
		slog.Any("error", err))

	// Try to add the route
	if err = netlink.RouteAdd(route); err != nil {
		slog.Error("failed to add route",
			slog.String("prefix", prefix),
			slog.String("gateway", gateway),
			slog.String("interface", ifaceName),
			slog.Any("error", err))
		return
	}

	slog.Info("route added",
		slog.String("prefix", prefix),
		slog.String("gateway", gateway),
		slog.String("interface", ifaceName))
}

func findInterfaceByIPv6(targetIP string) (*net.Interface, error) {
	if net.ParseIP(targetIP) == nil {
		slog.Warn("invalid IPv6 address", slog.String("targetIP", targetIP))
		return nil, nil // not an IPv6 address, skip
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		slog.Error("failed to list network interfaces", slog.Any("error", err))
		return nil, err
	}

	for _, iface := range interfaces {
		// Skip interfaces that are down or loopback
		if iface.Flags&net.FlagUp == 0 || iface.Name == "lo" {
			slog.Debug("skipping interface", slog.String("interface", iface.Name), slog.String("reason", "down or loopback"))
			continue
		}

		// Get the addresses associated with the interface
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			slog.Error("failed to get addresses for interface",
				slog.String("interface", iface.Name),
				slog.Any("error", err))
			return nil, err
		}

		// Check if the interface has the target IPv6 address
		for _, addr := range ifaceAddrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To16() != nil && ipNet.IP.String() == targetIP {
				slog.Info("interface found with matching IPv6 address",
					slog.String("interface", iface.Name),
					slog.String("IPv6", targetIP))
				return &iface, nil
			}
		}
	}

	slog.Warn("interface with IPv6 address not found", slog.String("targetIP", targetIP))
	return nil, fmt.Errorf("interface with IPv6 address %s not found", targetIP)
}
