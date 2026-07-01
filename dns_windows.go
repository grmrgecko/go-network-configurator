package netconfig

import (
	"context"
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// applyLiveDNSWindows applies the DNS servers and search domains to the live
// adapter via winipcfg, in addition to whatever the configuration backends
// persist. SetDNS on the adapter is per-family, so it is called for both IPv4
// and IPv6; winipcfg filters the server list to the matching family. Errors
// are logged but never returned, since a failure to update the live resolver
// does not undo the already-written persistent configuration.
func applyLiveDNSWindows(_ context.Context, iface string, servers []net.IP, searchDomains []string) {
	ipAdapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludePrefix|winipcfg.GAAFlagSkipAnycast|winipcfg.GAAFlagSkipMulticast|winipcfg.GAAFlagSkipDNSServer|winipcfg.GAAFlagSkipFriendlyName|winipcfg.GAAFlagSkipDNSInfo)
	if err != nil {
		logger.Printf("live DNS: list adapters: %v", err)
		return
	}
	var ipAdapter *winipcfg.IPAdapterAddresses
	for _, adap := range ipAdapters {
		if adap.FriendlyName() == iface {
			ipAdapter = adap
			break
		}
	}
	if ipAdapter == nil {
		logger.Printf("live DNS: no adapter found with name: %s", iface)
		return
	}

	var serverAddrs []netip.Addr
	for _, ip := range servers {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			serverAddrs = append(serverAddrs, netip.AddrFrom4([4]byte(v4)))
		} else if v16 := ip.To16(); v16 != nil {
			serverAddrs = append(serverAddrs, netip.AddrFrom16([16]byte(v16)))
		}
		// A net.IP that is neither a valid IPv4 nor IPv6 address is skipped
		// rather than converted, since [16]byte() on a short slice panics.
	}

	// SetDNS is per-family and filters the server list to the matching family,
	// so pass the full list to both calls. An empty list clears that family.
	if err := ipAdapter.LUID.SetDNS(winipcfg.AddressFamily(windows.AF_INET), serverAddrs, searchDomains); err != nil {
		logger.Printf("live DNS: set IPv4: %v", err)
	}
	if err := ipAdapter.LUID.SetDNS(winipcfg.AddressFamily(windows.AF_INET6), serverAddrs, searchDomains); err != nil {
		logger.Printf("live DNS: set IPv6: %v", err)
	}
}
