package netconfig

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const nodeworxBin = "/usr/bin/nodeworx"

type interworx struct {
}

// Move sites off the old IP to a new IP.
func (*interworx) moveSites(ctx context.Context, oldAddr, newAddr net.IP) error {
	cmd := exec.CommandContext(ctx, "/usr/local/interworx/bin/php", "/usr/local/interworx/bin/migrate-ip.php")

	// Get output pipes.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	// Send the IP addresses.

	// Start the command.
	err = cmd.Start()
	if err != nil {
		return err
	}

	// Setup wait group and buffer.
	var wg sync.WaitGroup
	wg.Add(2)

	// Setup expected line matching.
	oldMatch := regexp.MustCompile(`(?i)OLD IP Address`)
	newMatch := regexp.MustCompile(`(?i)NEW IP Address`)
	revokeMatch := regexp.MustCompile(`(?i)\[y/N\]`)

	// Read stdout, and provide answers to expected lines.
	var line strings.Builder
	go func() {
		for {
			// Read one byte to avoid lock up when the migrator asks for info.
			buf := make([]byte, 1)
			n, err := stdout.Read(buf)
			if err != nil || n != 1 {
				break
			}

			// If this is a new line, write the log and reset the line.
			if buf[0] == '\n' || buf[0] == '\r' {
				logger.Printf("Interworx migrate <stdout>: %s\n", line.String())
				line.Reset()
				continue
			}

			// Write the read byte to the buffer.
			line.Write(buf)

			// If the byte matches expected questions, answer them.
			if buf[0] == ']' {
				if revokeMatch.MatchString(line.String()) {
					fmt.Fprintln(stdin, "y")
				}
			} else if buf[0] == ':' {
				if oldMatch.MatchString(line.String()) {
					fmt.Fprintln(stdin, oldAddr.String())
				} else if newMatch.MatchString(line.String()) {
					fmt.Fprintln(stdin, newAddr.String())
				}
			}
		}
		wg.Done()
	}()

	// Read stderr.
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			logger.Printf("Interworx migrate <stderr>: %s\n", line)
		}
		wg.Done()
	}()

	// Wait for file reads to finish before.
	wg.Wait()

	// Wait for the command to finish.
	err = cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}

// Remove an IP address from interworx.
func (p *interworx) removeIP(ctx context.Context, addr net.IP) error {
	// We need the IP type.
	isIPv6 := addr.To4() == nil

	// Get list of IP addresses in nodeworx.
	out, err := runCommand(ctx, nodeworxBin, "-u", "-n", "-c", "Ip", "-a", "listIpAddresses")
	if err != nil {
		return err
	}

	// Data to capture from IP list.
	var sharedIP net.IP
	var publicIPs []net.IP
	var privateIPs []net.IP

	// Parse the IP list.
	found := false
	for _, line := range out {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse the IP field.
		ip := net.ParseIP(fields[0])
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
			found = true
			continue
		} else if fields[3] == "shared" && !ip.IsPrivate() {
			sharedIP = ip
		} else if !ip.IsPrivate() {
			publicIPs = append(publicIPs, ip)
		} else {
			pubIP := net.ParseIP(fields[1])
			if pubIP != nil && !pubIP.IsPrivate() {
				publicIPs = append(publicIPs, ip)
			} else {
				privateIPs = append(privateIPs, ip)
			}
		}
	}

	// An address InterWorx doesn't have has no sites to move, and nodeworx
	// refuses to delete it.
	if !found {
		return nil
	}

	// If no shared IP, try public IP and private IP association instead.
	if sharedIP == nil {
		if len(publicIPs) != 0 {
			sharedIP = publicIPs[0]
		} else if len(privateIPs) != 0 {
			sharedIP = privateIPs[0]
		} else {
			return fmt.Errorf("unable to find a shared IP to move ip addresses to")
		}
	}

	// Migrate sites to new shared IP.
	err = p.moveSites(ctx, addr, sharedIP)
	if err != nil {
		return err
	}

	// Wait briefly for the migration to propagate before removing the address.
	// The wait honours ctx cancellation so the caller can abort a stuck removal.
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}

	// Tell nodeworx to remove the IP address.
	out, err = runCommand(ctx, nodeworxBin, "-u", "-n", "-c", "Ip", "-a", "delete", "--confirm_action", "all", "--ip", addr.String())
	if err != nil {
		return err
	}
	if len(out) != 0 {
		logger.Println("Interworx output:", strings.Join(out, "\n"))
	}
	return nil
}

// setMainIP is a no-op for InterWorx. InterWorx changes the primary IP with the
// migrate-ip tool, which moves sites between IPs rather than repointing a stored
// main IP. That migration is performed by removeIP (via moveSites) when the old
// primary is removed, so promoting an address needs no separate action here.
func (*interworx) setMainIP(ctx context.Context, addr net.IP) error {
	return nil
}

// reload imports every address InterWorx offers to import. InterWorx 5 takes
// one address per `Ip import --ip`, from the choices it lists, and rejects
// "all"; with nothing to import, there is nothing to do.
func (p *interworx) reload(ctx context.Context) error {
	help, err := runCommand(ctx, nodeworxBin, "-u", "-n", "-c", "Ip", "-a", "import", "-h")
	if err != nil {
		return err
	}
	var errs []error
	for _, ip := range nodeworxChoices(help, "--ip") {
		out, err := runCommand(ctx, nodeworxBin, "-u", "-n", "-c", "Ip", "-a", "import", "--ip", ip)
		if err != nil {
			errs = append(errs, fmt.Errorf("importing %s: %w", ip, err))
			continue
		}
		if len(out) != 0 {
			logger.Println("Interworx output:", strings.Join(out, "\n"))
		}
	}
	return errors.Join(errs...)
}

// nodeworxChoices returns the values nodeworx's help lists for an option, as
// in "--ip <string>            192.0.2.10|2001:db8::10". An option listed
// without values has none to offer.
func nodeworxChoices(help []string, option string) []string {
	for _, line := range help {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != option {
			continue
		}
		if len(fields) < 3 {
			return nil
		}
		return strings.Split(fields[len(fields)-1], "|")
	}
	return nil
}
