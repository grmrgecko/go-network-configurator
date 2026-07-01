package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	cpanelBin  = "/usr/local/cpanel/bin/whmapi1"
	cpanelJSON = "--output=json"

	// Paths and scripts that define cPanel's main shared IPv4: mainip is the
	// stored main IP, ADDR in wwwacct.conf is the shared IP, and
	// mainipcheck/fixetchosts sync the stored main IP and /etc/hosts. IPv6 is
	// handled as ranges (see removeIP).
	cpanelWWWAcctConf = "/etc/wwwacct.conf"
	cpanelMainIP      = "/var/cpanel/mainip"
	cpanelMainIPCheck = "/scripts/mainipcheck"
	cpanelFixEtcHosts = "/scripts/fixetchosts"
)

type cpanelMetadata struct {
	Command string `json:"command"`
	Reason  string `json:"reason"`
	Result  int    `json:"result"`
}
type cpanelBase struct {
	Metadata cpanelMetadata `json:"metadata"`
}

type cpanelIPInfo struct {
	Active    int    `json:"active"`
	Dedicated int    `json:"dedicated"`
	IP        string `json:"ip"`
	MainIP    int    `json:"mainaddr"`
	PublicIP  string `json:"public_ip"`
	Removable int    `json:"removable"`
	Used      int    `json:"used"`
}
type cpanelListIPs struct {
	Data struct {
		IPs []cpanelIPInfo `json:"ip"`
	} `json:"data"`
	Metadata cpanelMetadata `json:"metadata"`
}

type cpanelAccountInfo struct {
	User   string   `json:"user"`
	Domain string   `json:"domain"`
	IP     string   `json:"ip"`
	IPv6   []string `json:"ipv6"`
}
type cpanelListAccounts struct {
	Data struct {
		Accounts []cpanelAccountInfo `json:"acct"`
	} `json:"data"`
	Metadata cpanelMetadata `json:"metadata"`
}

type cpanel struct {
}

// Parse cpanel API json output.
func (*cpanel) parseJSON(out []string, v any) error {
	if len(out) != 1 {
		return fmt.Errorf("no json output.")
	}

	return json.Unmarshal([]byte(out[0]), v)
}

// Move sites off the old IP to the new IP.
func (p *cpanel) moveSites(ctx context.Context, oldAddr, newAddr net.IP) error {
	// Get list of accounts in cPanel using the old IP.
	out, err := runCommand(ctx, cpanelBin, cpanelJSON, "listaccts", fmt.Sprintf("search=%s", oldAddr.String()), "searchtype=ip")
	if err != nil {
		return err
	}
	var data cpanelListAccounts
	err = p.parseJSON(out, &data)
	if err != nil {
		return err
	}

	// On error, log.
	if data.Metadata.Result != 1 {
		return fmt.Errorf("%s", data.Metadata.Reason)
	}

	// Move the sites to new IP.
	for _, account := range data.Data.Accounts {
		// If the IP is not the one we're removing, skip.'
		ip := net.ParseIP(account.IP)
		if !ip.Equal(oldAddr) {
			continue
		}

		// Update the IP address for the account.
		out, err := runCommand(ctx, cpanelBin, cpanelJSON, "setsiteip", fmt.Sprintf("ip=%s", newAddr.String()), fmt.Sprintf("user=%s", account.User))
		if err != nil {
			return err
		}
		var data cpanelBase
		err = p.parseJSON(out, &data)
		if err != nil {
			return err
		}
		logger.Println("cPanel site move response:", data.Metadata.Reason)
	}

	return nil
}

// Remove an IP address from cpanel. IPv4 and IPv6 are handled separately: the
// IPv4 main-IP pool (listips) is IPv4-only, so it must not be consulted when
// removing an IPv6 address.
func (p *cpanel) removeIP(ctx context.Context, addr net.IP) error {
	if addr.To4() == nil {
		return p.removeIPv6(ctx, addr)
	}
	return p.removeIPv4(ctx, addr)
}

// removeIPv4 moves accounts off addr onto cPanel's main shared IPv4, then
// releases addr.
func (p *cpanel) removeIPv4(ctx context.Context, addr net.IP) error {
	// Get list of accounts in cPanel using the old IP.
	out, err := runCommand(ctx, cpanelBin, cpanelJSON, "listaccts", fmt.Sprintf("search=%s", addr.String()), "searchtype=ip")
	if err != nil {
		return err
	}
	var accounts cpanelListAccounts
	err = p.parseJSON(out, &accounts)
	if err != nil {
		return err
	}
	if accounts.Metadata.Result != 1 {
		return fmt.Errorf("%s", accounts.Metadata.Reason)
	}

	// Get list of IP addresses in cPanel.
	out, err = runCommand(ctx, cpanelBin, cpanelJSON, "listips")
	if err != nil {
		return err
	}
	var data cpanelListIPs
	err = p.parseJSON(out, &data)
	if err != nil {
		return err
	}

	// On error, log.
	if data.Metadata.Result != 1 {
		return fmt.Errorf("%s", data.Metadata.Reason)
	}

	// Information to extract from IP list.
	var mainIP net.IP
	isMainIP := false
	var publicIPs []net.IP
	var privateIPs []net.IP

	// Parse IP list info.
	for _, ipInfo := range data.Data.IPs {
		ip := net.ParseIP(ipInfo.IP)

		// Depending on the ip, if the IP is one being removed we capture if its the main IP.
		// If the IP is the main IP, but no the one being removed, capture that fact.
		// If its an public IP, associate with public IP list, and if its private add as needed.
		if ip.Equal(addr) {
			isMainIP = ipInfo.MainIP == 1 && mainIP == nil
		} else if ipInfo.MainIP == 1 {
			mainIP = ip
			isMainIP = false
		} else if !ip.IsPrivate() {
			publicIPs = append(publicIPs, ip)
		} else {
			pubIP := net.ParseIP(ipInfo.PublicIP)
			if pubIP != nil && !pubIP.IsPrivate() {
				publicIPs = append(publicIPs, ip)
			} else {
				privateIPs = append(privateIPs, ip)
			}
		}
	}

	// If no main IP found, we should find a new main IP.
	noMainIP := mainIP == nil
	if noMainIP {
		if len(publicIPs) != 0 {
			mainIP = publicIPs[0]
		} else if len(privateIPs) != 0 {
			mainIP = privateIPs[0]
		} else {
			return fmt.Errorf("unable to find the main IP to move ip addresses to")
		}
	}

	// Move sites to the main IP from the old IP.
	err = p.moveSites(ctx, addr, mainIP)
	if err != nil {
		return err
	}

	// Remove the IP, incase there is an IP alias for it. We don't really care about the output for this,
	// it may fail if cPanel already picked up that the IP was removed from the system interface.
	runCommand(ctx, cpanelBin, cpanelJSON, "delip", fmt.Sprintf("ip=%s", addr.String()))

	// Rebuild the IP pool.
	err = p.reload(ctx)
	if err != nil {
		return err
	}

	// If the main IP did not exist, or if the IP being removed was the main IP, tell cPanel to check.
	if isMainIP || noMainIP {
		out, err := runCommand(ctx, cpanelMainIPCheck)
		if err != nil {
			return err
		}
		logger.Println("cPanel main IP output:", strings.Join(out, "\n"))
	}

	return nil
}

// removeIPv6 moves accounts off addr onto a replacement IPv6 address, then
// releases addr. cPanel's listips pool is IPv4-only, so the replacement is
// drawn from the other IPv6 addresses the affected accounts already hold; it is
// never an IPv4 address. When no other IPv6 is available the address is dropped
// from each account rather than substituted.
func (p *cpanel) removeIPv6(ctx context.Context, addr net.IP) error {
	// cPanel tracks IPv6 as ranges; search accounts by the IPv6 address.
	out, err := runCommand(ctx, cpanelBin, cpanelJSON, "listaccts", fmt.Sprintf("search=%s", addr.String()), "searchtype=ipv6")
	if err != nil {
		return err
	}
	var accounts cpanelListAccounts
	err = p.parseJSON(out, &accounts)
	if err != nil {
		return err
	}
	if accounts.Metadata.Result != 1 {
		return fmt.Errorf("%s", accounts.Metadata.Reason)
	}

	// Choose a replacement IPv6 from the addresses the affected accounts already
	// use, excluding the one being removed. Never fall back to an IPv4 address.
	var replacement net.IP
	for _, account := range accounts.Data.Accounts {
		for _, ipStr := range account.IPv6 {
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.To4() != nil || ip.Equal(addr) {
				continue
			}
			replacement = ip
			break
		}
		if replacement != nil {
			break
		}
	}

	// Move the sites off the address (onto the replacement, or drop it when
	// there is no other IPv6 to move to).
	err = p.moveIPv6Sites(ctx, accounts, addr, replacement)
	if err != nil {
		return err
	}

	// Remove the IP, incase there is an IP alias for it. We don't really care about the output for this,
	// it may fail if cPanel already picked up that the IP was removed from the system interface.
	runCommand(ctx, cpanelBin, cpanelJSON, "delip", fmt.Sprintf("ip=%s", addr.String()), "ipv6=1")

	// Rebuild the IP pool.
	return p.reload(ctx)
}

// moveIPv6Sites moves any accounts using oldAddr as an IPv6 address over to
// newAddr, or drops oldAddr from the account when newAddr is nil. cPanel
// exposes account IPv6 via listaccts, so we use that rather than the IPv4
// listips path.
func (p *cpanel) moveIPv6Sites(ctx context.Context, accounts cpanelListAccounts, oldAddr, newAddr net.IP) error {
	for _, account := range accounts.Data.Accounts {
		// Confirm the account actually has the address being removed.
		found := false
		for _, ip := range account.IPv6 {
			if net.ParseIP(ip).Equal(oldAddr) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// Build the new IPv6 list, replacing oldAddr with newAddr. When there is
		// no replacement (newAddr is nil), drop oldAddr from the list entirely
		// rather than substituting an address of the wrong family.
		var newIPv6 []string
		for _, ip := range account.IPv6 {
			if net.ParseIP(ip).Equal(oldAddr) {
				if newAddr != nil {
					newIPv6 = append(newIPv6, newAddr.String())
				}
			} else {
				newIPv6 = append(newIPv6, ip)
			}
		}

		out, err := runCommand(ctx, cpanelBin, cpanelJSON, "setsiteip", fmt.Sprintf("ip=%s", account.IP), fmt.Sprintf("user=%s", account.User), fmt.Sprintf("ipv6=%s", strings.Join(newIPv6, ",")))
		if err != nil {
			return err
		}
		var data cpanelBase
		err = p.parseJSON(out, &data)
		if err != nil {
			return err
		}
		logger.Println("cPanel IPv6 site move response:", data.Metadata.Reason)
	}
	return nil
}

// setWWWAcctAddr rewrites an address directive in a wwwacct.conf-style file to
// ip in place, preserving every other line and the file's permissions. If the
// directive is absent it is appended. directive is "ADDR" for the shared IPv4 or
// "ADDR6" for the shared IPv6; the two are distinct, so setting one leaves the
// other untouched.
func setWWWAcctAddr(path, directive, ip string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] == directive {
			lines[i] = directive + " " + ip
			replaced = true
		}
	}
	if !replaced {
		// Insert before a trailing empty element (from a final newline) so the
		// file keeps a single trailing newline rather than gaining a blank line.
		if n := len(lines); n > 0 && lines[n-1] == "" {
			lines = append(lines[:n-1], directive+" "+ip, "")
		} else {
			lines = append(lines, directive+" "+ip)
		}
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), info.Mode().Perm())
}

// setMainIP repoints cPanel's main shared IP to addr: set the shared-IP
// directive in wwwacct.conf (ADDR for IPv4, ADDR6 for IPv6), then run
// mainipcheck and fixetchosts to sync the stored main IP and /etc/hosts. Only
// IPv4 has a stored-main-IP file (/var/cpanel/mainip); IPv6 is tracked as ranges
// and has no such file. The IP pool (/etc/ipaddrpool) is not written here
// because reload() runs /scripts/rebuildippool, which rebuilds the pool from the
// system's bound IPs.
func (p *cpanel) setMainIP(ctx context.Context, addr net.IP) error {
	ip := addr.String()

	// Point the shared IP at the new main address (ADDR6 for IPv6).
	directive := "ADDR"
	if addr.To4() == nil {
		directive = "ADDR6"
	}
	if err := setWWWAcctAddr(cpanelWWWAcctConf, directive, ip); err != nil {
		return err
	}

	// Only IPv4 has a stored main IP file; record it without a trailing newline.
	if addr.To4() != nil {
		if err := os.WriteFile(cpanelMainIP, []byte(ip), 0644); err != nil {
			return err
		}
	}

	// Sync cPanel's stored main IP (/var/cpanel/mainip) and /etc/hosts.
	out, err := runCommand(ctx, cpanelMainIPCheck)
	if err != nil {
		return err
	}
	logger.Println("cPanel main IP output:", strings.Join(out, "\n"))
	runCommand(ctx, cpanelFixEtcHosts)
	return nil
}

// Tell cpanel to reload the available IP addresses.
func (*cpanel) reload(ctx context.Context) error {
	out, err := runCommand(ctx, "/scripts/rebuildippool")
	if err != nil {
		return err
	}
	logger.Println("cPanel IP pool output:", strings.Join(out, "\n"))
	return nil
}
