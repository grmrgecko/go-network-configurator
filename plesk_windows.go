package netconfig

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const pleskBin = `C:\Program Files (x86)\Plesk\bin\plesk.exe`

type plesk struct {
}

// parsePleskIPField extracts the IP address from a field produced by
// `plesk bin ipmanage --ip_list`. The field has the form
// "<interface>:<ip>[/<mask>]"; missing components result in a nil IP so the
// line is skipped rather than crashing the process.
func parsePleskIPField(s string) net.IP {
	// Drop an optional "/<mask>".
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	// The field may be just the IP, or "<interface>:<ip>". Try the whole
	// string first; if it does not parse, drop the interface prefix up to
	// the first colon. IPv6 addresses contain colons, so LastIndex would
	// truncate the final hextet.
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[idx+1:]
		// If the IP was compressed with a leading "::", the interface
		// prefix consumed one of the leading colons (e.g. "eth0::1").
		if strings.HasPrefix(s, ":") {
			s = ":" + s
		}
		return net.ParseIP(s)
	}
	return nil
}

// Move sites off the old IP to a new IP.
func (*plesk) moveSites(ctx context.Context, oldAddr, newAddr net.IP) error {
	// We need the IP type.
	isIPv6 := oldAddr.To4() == nil

	// Get list of IP addresses from plesk.
	domains, err := runCommand(ctx, pleskBin, "bin", "domain", "--list")
	if err != nil {
		return err
	}

	// Domain info parser.
	dataParse := regexp.MustCompile(`^([^:]+):\s*([^$]+)$`)

	// Check each domain for the old IP, and update to either remove or move to the new IP.
	for _, domain := range domains {
		// Get the domain info.
		out, err := runCommand(ctx, pleskBin, "bin", "domain", "--info", domain)
		if err != nil {
			return err
		}

		// Parse the domain info IP addresses.
		var domainIPv4 []net.IP
		var domainIPv6 []net.IP
		for _, line := range out {
			// Parse and skip lines that do not match.
			match := dataParse.FindAllStringSubmatch(line, 1)
			if len(match) == 0 {
				continue
			}

			// Get the key/value from the parsed info.
			key := strings.TrimSpace(match[0][1])
			value := strings.TrimSpace(match[0][2])

			// If this is the IP address configuration, parse the IP addresses assigned.
			if key == "IP Address" {
				ipAddrs := strings.Split(value, ", ")
				for _, ipAddr := range ipAddrs {
					ip := net.ParseIP(ipAddr)
					if ip.To4() == nil {
						domainIPv6 = append(domainIPv6, ip)
					} else {
						domainIPv4 = append(domainIPv4, ip)
					}
				}
			}
		}

		// Look for the old IP according to its type, and remove and or replace with the new IP if there are no other
		// IP addresses of its type.
		foundOld := false
		if isIPv6 {
			for i, ip := range domainIPv6 {
				if ip.Equal(oldAddr) {
					foundOld = true
					domainIPv6 = append(domainIPv6[:i], domainIPv6[i+1:]...)
				}
			}
			if foundOld && len(domainIPv6) == 0 {
				domainIPv6 = append(domainIPv6, newAddr)
			}
		} else {
			for i, ip := range domainIPv4 {
				if ip.Equal(oldAddr) {
					foundOld = true
					domainIPv4 = append(domainIPv4[:i], domainIPv4[i+1:]...)
				}
			}
			if foundOld && len(domainIPv4) == 0 {
				domainIPv4 = append(domainIPv4, newAddr)
			}
		}

		// If we found the old IP, run the domain update command to update the sites association.
		if foundOld {
			var domainIPs []string
			for _, ip := range domainIPv4 {
				domainIPs = append(domainIPs, ip.String())
			}
			for _, ip := range domainIPv6 {
				domainIPs = append(domainIPs, ip.String())
			}
			out, err := runCommand(ctx, pleskBin, "bin", "domain", "--update", domain, "-ip", strings.Join(domainIPs, ","))
			if err != nil {
				return err
			}
			logger.Println("Plesk domain output:", strings.Join(out, "\n"))
		}
	}

	return nil
}

// Remove an IP address from Plesk.
func (p *plesk) removeIP(ctx context.Context, addr net.IP) error {
	// We need the IP type.
	isIPv6 := addr.To4() == nil

	// Get list of IP addresses from plesk.
	out, err := runCommand(ctx, pleskBin, "bin", "ipmanage", "--ip_list")
	if err != nil {
		return err
	}

	// We should capture these fields from the list.
	ipHosting := 0
	var sharedIP net.IP
	var publicIPs []net.IP
	var privateIPs []net.IP

	// Parse each line returned from plesk.
	for _, line := range out {
		fields := strings.Fields(line)

		// Skip blank or malformed lines that lack the fields parsed below.
		if len(fields) < 5 {
			continue
		}

		// Skip the header line.
		if fields[2] == "IP" {
			continue
		}

		// Parse the IP field.
		ip := parsePleskIPField(fields[2])
		if ip == nil {
			continue
		}

		// Skip IP addresses of a different type.
		if ip.To4() == nil && !isIPv6 {
			continue
		} else if ip.To4() != nil && isIPv6 {
			continue
		}

		// Depending on IP match, apply to fields. When we find the address we are removing,
		// we should determine how may sites are hosted by the IP. If the type is an shared iP,
		// set the shared IP to it. Otherwise, associate other IP types to public/private IP
		// lists to allow us to select an IP where a shared IP doesn't exist.
		if ip.Equal(addr) {
			ipHosting, _ = strconv.Atoi(fields[4])
		} else if fields[1] == "S" {
			sharedIP = ip
		} else if !ip.IsPrivate() {
			publicIPs = append(publicIPs, ip)
		} else {
			if len(fields) == 6 {
				pubIP := net.ParseIP(fields[5])
				if pubIP != nil {
					publicIPs = append(publicIPs, ip)
				} else {
					privateIPs = append(privateIPs, ip)
				}
			} else {
				privateIPs = append(privateIPs, ip)
			}
		}
	}

	// If no shared IP, try public IP and private IP association instead.
	if sharedIP == nil {
		if len(publicIPs) != 0 {
			sharedIP = publicIPs[0]
		} else if len(privateIPs) != 0 {
			sharedIP = privateIPs[0]
		} else if ipHosting != 0 {
			return fmt.Errorf("unable to find a shared IP to move ip addresses to")
		}
	}

	// If the IP we are removing is hosting sites, move the sites to the shared IP determined above.
	if ipHosting != 0 {
		err := p.moveSites(ctx, addr, sharedIP)
		if err != nil {
			return err
		}
	}

	// Remove the IP address from plesk.
	out, err = runCommand(ctx, pleskBin, "bin", "ipmanage", "--remove", addr.String())
	if err != nil {
		return err
	}
	logger.Println("Plesk output:", strings.Join(out, "\n"))
	return nil
}

// setMainIP repoints Plesk's main IP to addr. There is no `plesk bin ipmanage`
// flag for this, so the main flag is set directly in the psa database's
// IP_Addresses table via `plesk db`, which authenticates automatically. The new
// address is promoted first so there is never a window with no main IP, then
// every other address is demoted, leaving exactly one main row.
func (p *plesk) setMainIP(ctx context.Context, addr net.IP) error {
	ip := addr.String()
	queries := []string{
		fmt.Sprintf("UPDATE IP_Addresses SET main='true' WHERE ip_address='%s'", ip),
		fmt.Sprintf("UPDATE IP_Addresses SET main='false' WHERE ip_address<>'%s'", ip),
	}
	for _, query := range queries {
		out, err := runCommand(ctx, pleskBin, "db", query)
		if err != nil {
			return err
		}
		if len(out) != 0 {
			logger.Println("Plesk db output:", strings.Join(out, "\n"))
		}
	}
	return nil
}

// Tell plesk to reload the available IP addresses.
func (*plesk) reload(ctx context.Context) error {
	out, err := runCommand(ctx, pleskBin, "bin", "ipmanage", "--reread")
	if err != nil {
		return err
	}
	logger.Println("Plesk output:", strings.Join(out, "\n"))
	return nil
}
