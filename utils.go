package netconfig

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus-community/pro-bing"
)

// Handle values that can be an integer or a string.
type intString struct {
	Int    *int
	String *string
}

func (i *intString) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var asInt int
	var err error
	if err = unmarshal(&asInt); err == nil {
		i.Int = &asInt
		return nil
	}
	var asString string
	if err = unmarshal(&asString); err == nil {
		i.String = &asString
		return nil
	}
	return fmt.Errorf("not valid as an int or a string: %v", err)
}

func (i intString) MarshalYAML() (interface{}, error) {
	if i.Int != nil {
		return *i.Int, nil
	} else if i.String != nil {
		return *i.String, nil
	}
	return nil, nil
}

func (i *intString) UnmarshalJSON(data []byte) error {
	var asInt int
	var err error
	if err = json.Unmarshal(data, &asInt); err == nil {
		i.Int = &asInt
		return nil
	}
	var asString string
	if err = json.Unmarshal(data, &asString); err == nil {
		i.String = &asString
		return nil
	}
	return fmt.Errorf("not valid as an int or a string: %v", err)
}

func (i intString) MarshalJSON() ([]byte, error) {
	if i.Int != nil {
		return json.Marshal(*i.Int)
	} else if i.String != nil {
		return json.Marshal(*i.String)
	}
	return nil, nil
}

// Custom type to sort an directory listing.
type sortableDirEntries []os.DirEntry

func (fil sortableDirEntries) Len() int {
	return len(fil)
}

func (fil sortableDirEntries) Less(i, j int) bool {
	return fil[i].Name() < fil[j].Name()
}

func (fil sortableDirEntries) Swap(i, j int) {
	fil[i], fil[j] = fil[j], fil[i]
}

// Convert an uint32 to net.IP.
func uint2IP(u uint32) net.IP {
	bs := []byte{0, 0, 0, 0}
	binary.LittleEndian.PutUint32(bs, u)
	return net.IP(bs)
}

// Convert an net.IP to uint32 format.
func ip2Uint(ip net.IP) uint32 {
	if len(ip) == 16 {
		ip = ip[12:]
	}
	return binary.LittleEndian.Uint32(ip)
}

// Run command and return errors and stdout. The command is bound to ctx, so a
// cancelled or expired context terminates it.
func runCommand(ctx context.Context, command string, args ...string) (out []string, err error) {
	cmd := exec.CommandContext(ctx, command, args...)
	hideCommandWindow(cmd)

	// Get output pipes.
	var stdout, stderr io.ReadCloser
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	stderr, err = cmd.StderrPipe()
	if err != nil {
		return
	}

	// Start the command.
	err = cmd.Start()
	if err != nil {
		return
	}

	// Setup wait group to wait for buffers to fully read.
	var wg sync.WaitGroup
	wg.Add(2)

	// Read stdout.
	stdoutScanner := bufio.NewScanner(stdout)
	go func() {
		for stdoutScanner.Scan() {
			out = append(out, stdoutScanner.Text())
		}
		wg.Done()
	}()

	// Read stderr.
	var stderrData strings.Builder
	stderrScanner := bufio.NewScanner(stderr)
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			stderrData.WriteString(line)
		}
		wg.Done()
	}()

	// Wait for file reads to finish before.
	wg.Wait()

	// Wait for the command to finish.
	err = cmd.Wait()
	if err != nil {
		stderr := stderrData.String()
		if stderr != "" {
			err = fmt.Errorf("%v (stdout %s)", stderr, strings.Join(out, "\n"))
		}
		return
	}
	return
}

// naturalLess compares two strings the way a person reads them, comparing a run
// of digits by the number it spells rather than character by character, so eth2
// sorts before eth10 and enp0s3 before enp0s10. Digit runs are compared without
// being parsed, so a name carrying a number too large for an integer still
// orders sensibly.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		if isDigit(a[0]) && isDigit(b[0]) {
			var aNum, bNum string
			aNum, a = leadingDigits(a)
			bNum, b = leadingDigits(b)
			// Leading zeros change the text but not the value.
			aNum = strings.TrimLeft(aNum, "0")
			bNum = strings.TrimLeft(bNum, "0")
			if len(aNum) != len(bNum) {
				return len(aNum) < len(bNum)
			}
			if aNum != bNum {
				return aNum < bNum
			}
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

// isDigit reports whether c is an ASCII digit.
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// leadingDigits splits s into its leading run of digits and the rest.
func leadingDigits(s string) (digits, rest string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

// ipStrings converts a list of IPs to their string form, skipping nil entries.
func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

// IPv6 has the option to store IPv4 addresses, this is a prefix to determine that.
var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// Confirm that an byte array is all FF.
func allFF(b []byte) bool {
	for _, c := range b {
		if c != 0xff {
			return false
		}
	}
	return true
}

// Get broadcast address.
func getBroadcast(network *net.IPNet) net.IP {
	mask := network.Mask
	ip := network.IP

	// Ensure mask and IP are same family.
	if len(mask) == net.IPv6len && len(ip) == net.IPv4len && allFF(mask[:12]) {
		mask = mask[12:]
	}
	if len(mask) == net.IPv4len && len(ip) == net.IPv6len && bytes.Equal(ip[:12], v4InV6Prefix) {
		ip = ip[12:]
	}
	n := len(ip)

	// Make byte array and make broadcast.
	broadCast := make(net.IP, n)
	for i := 0; i < n; i++ {
		invertedMask := mask[i] ^ 0xff
		broadCast[i] = (ip[i] & mask[i]) | invertedMask
	}
	return broadCast
}

// Confirm ping results in packets received. The ping run is bound to ctx, so a
// cancelled context ends it early. count is the number of probes; timeout is
// the overall bound on the run.
func pingTest(ctx context.Context, dest string, count int, timeout time.Duration) bool {
	pinger, err := probing.NewPinger(dest)
	if err != nil {
		return false
	}
	if count <= 0 {
		count = defaultPingCount
	}
	pinger.Count = count
	if timeout <= 0 {
		timeout = defaultPingTimeout
	}
	pinger.Timeout = timeout
	err = pinger.RunWithContext(ctx)
	if err != nil {
		return false
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return false
	}
	return true
}

// Perform an HTTP request to confirm internet connection. The request is bound
// to ctx (in addition to a hard timeout), so a cancelled context aborts it. A
// response is only treated as success when its status code indicates the
// request was actually served (2xx or 3xx), so a captive portal or error page
// does not read as connectivity.
func testInternet(ctx context.Context, testAddress string, timeout time.Duration) bool {
	if testAddress == "test_success" {
		return true
	} else if testAddress == "test_fail" {
		return false
	}
	if timeout <= 0 {
		timeout = defaultConnectivityTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testAddress, nil)
	if err != nil {
		logger.Printf("internet connectivity test failed: %v", err)
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("internet connectivity test failed: %v", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		logger.Printf("internet connectivity test failed: status %s", resp.Status)
		return false
	}
	return true
}

// A file move wrapper that handles cross device moving.
func fileMove(source, destination string) error {
	// Attempt to move using normal rename.
	err := os.Rename(source, destination)

	// If we get a cross device move error, try copying instead.
	if err != nil {
		if le, ok := err.(*os.LinkError); ok && errors.Is(le.Err, syscall.EXDEV) {
			return fileMoveCopy(source, destination)
		}
		// Fallback for implementations that wrap EXDEV differently.
		if errors.Is(err, syscall.EXDEV) {
			return fileMoveCopy(source, destination)
		}
	}

	// Otherwise return error.
	return err
}

// Copy a file.
func fileCopy(source, destination string) error {
	// Open the source for reading.
	src, err := os.Open(source)
	if err != nil {
		return err
	}

	// Open destination for wrtiting.
	dst, err := os.Create(destination)
	if err != nil {
		src.Close()
		return err
	}

	// Copy file contents.
	_, err = io.Copy(dst, src)

	// Close both files.
	src.Close()
	dst.Close()

	// If copying returned an error, return that error.
	if err != nil {
		os.Remove(destination)
		return err
	}

	// Get original file permissions.
	fi, err := os.Stat(source)
	if err != nil {
		os.Remove(destination)
		return err
	}

	// Correct the destination file mode.
	err = os.Chmod(destination, fi.Mode())
	if err != nil {
		os.Remove(destination)
		return err
	}
	return nil
}

// This moves by copying a file instead of renaming.
func fileMoveCopy(source, destination string) error {
	// Copy the file.
	err := fileCopy(source, destination)
	if err != nil {
		os.Remove(destination)
		return err
	}

	// Remove original source.
	os.Remove(source)
	return nil
}

// pruneBackups removes all but the keep most-recently-modified files in dir for
// which match returns true. A non-positive keep disables pruning (every backup
// is kept). Errors are logged and otherwise ignored, since leftover backup
// files are not fatal. Backups are ordered by modification time so the keep
// newest survive regardless of how the timestamp is encoded in the file name.
func pruneBackups(dir string, match func(name string) bool, keep int) {
	if keep <= 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type backup struct {
		name  string
		mtime time.Time
	}
	var backups []backup
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if match != nil && !match(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backup{e.Name(), info.ModTime()})
	}
	if len(backups) <= keep {
		return
	}
	sort.Slice(backups, func(i, j int) bool {
		if !backups[i].mtime.Equal(backups[j].mtime) {
			return backups[i].mtime.After(backups[j].mtime)
		}
		return backups[i].name > backups[j].name
	})
	for _, b := range backups[keep:] {
		if err := os.Remove(filepath.Join(dir, b.name)); err != nil {
			logger.Printf("pruneBackups: remove %s: %v", b.name, err)
		}
	}
}

// suffixBackupMatcher matches backups named "base.bak.<ts>" (the netplan,
// networkd, and cloud-init naming).
func suffixBackupMatcher(base string) func(string) bool {
	prefix := base + ".bak."
	return func(name string) bool { return strings.HasPrefix(name, prefix) }
}

// prefixBackupMatcher matches backups named ".bak.<ts>.base" (the network-scripts
// and ifupdown naming).
func prefixBackupMatcher(base string) func(string) bool {
	return func(name string) bool {
		return strings.HasPrefix(name, ".bak.") && strings.HasSuffix(name, "."+base)
	}
}
