package main

import (
	"fmt"
	"log"
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
	log.Printf("current capabilities: %s", cap.GetProc())
	caps := cap.NewSet()
	if err := caps.SetFlag(cap.Effective, true, cap.NET_RAW, cap.NET_ADMIN); err != nil {
		log.Fatalf("failed to set cap: %v", err)
	}

	var (
		routerIPs []string
	)

	if len(os.Args) > 1 {
		routerIPs = os.Args[1:]
		log.Print("routerIPs:", routerIPs)
	}

	if len(routerIPs) == 0 {
		log.Fatalf("Usage: %s <router-ip1> [router-ip2] ...", os.Args[0])
	}

	var (
		ifi *net.Interface
		err error
	)

	if os.Getenv("INTERFACE_NAME") != "" {
		if ifi, err = net.InterfaceByName(os.Getenv("INTERFACE_NAME")); err != nil {
			log.Fatalf("failed to find interface: %v", err)
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
		log.Fatalf("no interface found")
	}
	log.Println("using interface:", ifi.Name)

	conn, _, err := ndp.Listen(ifi, ndp.Addr(string(ndp.LinkLocal)))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
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
		log.Fatalf("failed to parse sync interval: %v", err)
	}

	for {
		log.Println("running sync")
		for _, ip := range ips {
			routeInfoChan := make(chan []*ndp.RouteInformation)
			go receiveRA(conn, ip, routeInfoChan) // start receiving RAs
			go sendRS(conn, rsMsg, ip)            // start sending RSs

			for _, rinfo := range <-routeInfoChan {
				addRoute(fmt.Sprintf("%s/%d", rinfo.Prefix, rinfo.PrefixLength), ip.String(), ifi.Name)
			}
		}
		log.Println("sync completed")
		time.Sleep(syncIntervalDuration)
	}
}

// Send a router solicitation
func sendRS(conn *ndp.Conn, msg *ndp.RouterSolicitation, dst netip.Addr) {
	if err := conn.WriteTo(msg, nil, dst); err != nil {
		log.Fatalf("failed to write to: %v", err)
	}
	log.Printf("sent router solicitation to %s", dst)
}

// Receive a router advertisement and process the route information
func receiveRA(conn *ndp.Conn, dst netip.Addr, routeInfoChan chan<- []*ndp.RouteInformation) {
	for {
		respMsg, _, respAddr, err := conn.ReadFrom()
		if err != nil {
			log.Fatalf("failed to read from: %v", err)
		}
		if respAddr.As16() != dst.As16() {
			log.Printf("received msg from %s, expected %s, skipping", respAddr, dst)
			continue
		}
		ra, ok := respMsg.(*ndp.RouterAdvertisement)
		if !ok {
			log.Printf("received msg type: %s, skipping", respMsg.Type())
			continue
		}

		routeInfo := []*ndp.RouteInformation{}
		for _, o := range ra.Options {
			if rinfo, ok := o.(*ndp.RouteInformation); ok {
				routeInfo = append(routeInfo, rinfo)
			}

		}

		routeInfoChan <- routeInfo
		return
	}
}

func addRoute(prefix, gateway, ifaceName string) {
	_, dst, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Printf("Invalid prefix %s: %v", prefix, err)
		return
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		log.Printf("Invalid gateway IP %s", gateway)
		return
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Printf("Failed to find interface %s: %v", ifaceName, err)
		return
	}

	if commit := os.Getenv("COMMIT"); commit == "" {
		log.Printf("COMMIT != true; would have added route: %s via %s dev %s", prefix, gateway, ifaceName)
		return
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}

	// Try to replace the route
	if err = netlink.RouteReplace(route); err == nil {
		log.Printf("Route replaced: %s via %s dev %s", prefix, gateway, ifaceName)
		return
	}

	log.Printf("Failed to replace route: %v. Attempting to add route instead...", err)
	if err = netlink.RouteAdd(route); err != nil {
		log.Printf("Failed to add route: %v", err)
		return
	}

	log.Printf("Route added: %s via %s dev %s", prefix, gateway, ifaceName)
}

func findInterfaceByIPv6(targetIP string) (*net.Interface, error) {
	if net.ParseIP(targetIP) == nil {
		return nil, nil // not an IPv6 address, skip
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Name == "lo" {
			continue
		}

		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range ifaceAddrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To16() != nil && ipNet.IP.String() == targetIP {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("interface with IPv6 address %s not found", targetIP)
}
