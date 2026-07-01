package netconfig

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	resolvectlBin = "resolvectl"
	resolvConf    = "/etc/resolv.conf"
)

// applyLiveDNS applies the DNS servers and search domains to the running
// resolver in addition to whatever the configuration backends persist. It is
// best-effort: errors are logged but never returned, because a failure to
// update the live resolver does not undo the (already-written) persistent
// configuration.
//
// Two mechanisms are used, in order of preference:
//  1. systemd-resolved via resolvectl, which keeps DNS per-interface and is the
//     correct mechanism when resolved manages /etc/resolv.conf.
//  2. A direct rewrite of /etc/resolv.conf, used only when resolvectl is absent
//     and the file is a regular file (not a symlink to the resolved stub). This
//     is a global resolver change rather than a per-interface one.
func applyLiveDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) {
	serverStrs := ipStrings(servers)
	if _, err := exec.LookPath(resolvectlBin); err == nil {
		if applyResolvectlDNS(ctx, iface, serverStrs, searchDomains) {
			return
		}
		logger.Println("live DNS: resolvectl failed, falling back to /etc/resolv.conf")
	}
	// The /etc/resolv.conf fallback is a global change with no per-interface
	// concept, so an empty server list would strip every nameserver and take
	// down all resolution on the host. Clearing DNS is only meaningful
	// per-interface (handled above by resolvectl), so skip the file rewrite
	// rather than wipe the global resolver.
	if len(serverStrs) == 0 {
		return
	}
	if err := writeResolvConf(serverStrs, searchDomains); err != nil {
		logger.Printf("live DNS: %v", err)
	}
}

// applyResolvectlDNS sets per-interface DNS servers and search domains via
// resolvectl. An empty server/domain list clears that field for the interface.
// It returns true if the resolvectl calls succeeded.
func applyResolvectlDNS(ctx context.Context, iface string, servers, searchDomains []string) bool {
	// When both lists are empty the intent is to drop this interface's DNS
	// entirely; "resolvectl revert LINK" is the documented reset and avoids
	// relying on the version-sensitive behaviour of passing an empty string.
	if len(servers) == 0 && len(searchDomains) == 0 {
		if _, err := runCommand(ctx, resolvectlBin, "revert", iface); err != nil {
			logger.Printf("live DNS: resolvectl revert: %v", err)
			return false
		}
		return true
	}

	ok := true
	// resolvectl dns LINK [SERVER...]; passing a single empty string clears the
	// per-link server list.
	dnsArgs := []string{"dns", iface}
	if len(servers) > 0 {
		dnsArgs = append(dnsArgs, servers...)
	} else {
		dnsArgs = append(dnsArgs, "")
	}
	if _, err := runCommand(ctx, resolvectlBin, dnsArgs...); err != nil {
		logger.Printf("live DNS: resolvectl dns: %v", err)
		ok = false
	}

	// resolvectl domain LINK [DOMAIN...]; passing a single empty string clears
	// the per-link search list.
	domainArgs := []string{"domain", iface}
	if len(searchDomains) > 0 {
		domainArgs = append(domainArgs, searchDomains...)
	} else {
		domainArgs = append(domainArgs, "")
	}
	if _, err := runCommand(ctx, resolvectlBin, domainArgs...); err != nil {
		logger.Printf("live DNS: resolvectl domain: %v", err)
		ok = false
	}
	return ok
}

// writeResolvConf rewrites /etc/resolv.conf with the given servers and search
// domains, preserving any non-nameserver/non-search lines (comments, options,
// etc.). It only writes a regular file: when /etc/resolv.conf is a symlink (as
// it is when managed by systemd-resolved or resolvconf), it is left untouched
// so the manager keeps ownership.
func writeResolvConf(servers, searchDomains []string) error {
	fi, err := os.Lstat(resolvConf)
	if err != nil {
		return fmt.Errorf("stat %s: %w", resolvConf, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		// resolv.conf is a symlink to a manager-owned target; do not clobber it.
		return nil
	}
	perm := fi.Mode().Perm()

	data, err := os.ReadFile(resolvConf)
	if err != nil {
		return fmt.Errorf("read %s: %w", resolvConf, err)
	}

	var kept []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		field := strings.Fields(scanner.Text())
		if len(field) > 0 && (field[0] == "nameserver" || field[0] == "search") {
			continue
		}
		kept = append(kept, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", resolvConf, err)
	}

	var b strings.Builder
	for _, line := range kept {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if len(searchDomains) > 0 {
		b.WriteString("search ")
		b.WriteString(strings.Join(searchDomains, " "))
		b.WriteByte('\n')
	}
	for _, s := range servers {
		b.WriteString("nameserver ")
		b.WriteString(s)
		b.WriteByte('\n')
	}

	tmp := resolvConf + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), perm); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := fileMove(tmp, resolvConf); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("commit %s: %w", resolvConf, err)
	}
	return nil
}
