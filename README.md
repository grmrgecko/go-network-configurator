# go-network-configurator

[![Go Reference](https://pkg.go.dev/badge/github.com/grmrgecko/go-network-configurator.svg)](https://pkg.go.dev/github.com/grmrgecko/go-network-configurator)

A Go library for inspecting and changing a host's IP addresses and static
routes at runtime **and** persisting those changes to whatever on-disk network
configuration backend the system actually uses — so the change survives a
reboot.

It is designed for hosting environments where an automated system needs to add,
swap, or remove IPs on a server without knowing in advance whether that server
is running netplan, systemd-networkd, NetworkManager, RHEL network-scripts,
ifupdown, or cloud-init — and without leaving a control panel (cPanel, Plesk,
InterWorx) out of sync.

```go
import "github.com/grmrgecko/go-network-configurator"
```

## How it works

A single `Configurator` applies every change in two layers:

1. **Runtime** — the live kernel state is changed immediately (via netlink on
   Linux, the IP Helper API on Windows). Address and gateway changes are
   verified against an internet-reachability test and **rolled back
   automatically** if connectivity is lost.
2. **Persistence** — the same change is written to every detected configuration
   backend so it survives a reboot, and registered control panels are told to
   re-read the system's IPs.

Backends are auto-detected at construction time. A host running both netplan and
cloud-init, for example, has both files kept in sync; a failure writing one
backend is logged but does not abort the others.

## Supported backends

**Network configuration (persistence)**

| Backend             | Detection                                   |
| ------------------- | ------------------------------------------- |
| netplan             | `netplan` binary on `PATH`                  |
| cloud-init          | cloud-init network config present           |
| NetworkManager      | `NetworkManager.service` active             |
| systemd-networkd    | `systemd-networkd.service` active           |
| RHEL network-scripts| `network.service` active (config dir on legacy hosts) |
| ifupdown            | `/etc/network/interfaces`                   |

**Control panels**

| Panel     | Detection                          |
| --------- | ---------------------------------- |
| cPanel    | `/usr/local/cpanel/bin/whmapi1`    |
| Plesk     | `/usr/sbin/plesk`                  |
| InterWorx | `/usr/bin/nodeworx`                |

Detection of the service-managed backends (NetworkManager, systemd-networkd,
and RHEL network-scripts) uses systemd over D-Bus, with a fallback for legacy
systems that lack a usable systemd D-Bus interface (Ubuntu 14.04 Upstart,
CentOS 5/6). On that fallback path network-scripts is detected by the presence
of its `/etc/sysconfig/network-scripts` directory.

## Platforms

- **Linux** — full support (all backends and panels above).
- **Windows** — runtime changes via the IP Helper API, persisted to cloud-init,
  with Plesk panel support.

## API

```go
type Configurator interface {
    // Enumerate interfaces with their addresses, gateways, static routes,
    // DNS servers, and search domains.
    GetInterfaces(ctx context.Context) ([]*Interface, error)

    // Add an IP address (optionally setting/replacing the default gateway).
    AddAddress(ctx context.Context, iface string, addr *net.IPNet, gateway net.IP) error

    // Promote an address already on the interface to be the primary of its family.
    SetPrimaryAddress(ctx context.Context, iface string, addr *net.IPNet) error

    // Remove an IP address.
    RemoveAddress(ctx context.Context, iface string, addr *net.IPNet) error

    // Add or remove a static route.
    AddRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP, metric int) error
    RemoveRoute(ctx context.Context, iface string, dst *net.IPNet, gateway net.IP) error

    // Set the DNS servers and search domains for an interface.
    SetDNS(ctx context.Context, iface string, servers []net.IP, searchDomains []string) error
}

// Construct the configurator for the current OS, auto-detecting backends.
// Behaviour is tuned with Option values (see Options below).
func NewConfigurator(opts ...Option) (Configurator, error)

// Resolve an interface by name, or by the special "public-internet" /
// "public-internet-6" selectors.
func FindInterfaceByName(name string, ifaces []*Interface) *Interface
```

Every operation takes a `context.Context`. The slow steps — the ICMP probe of a
new gateway and the internet-reachability test — honour cancellation and
deadlines, so a caller can bound how long a change may block.

### DNS

`SetDNS` applies an interface's resolvers and search domains to the live
resolver so they take effect immediately, and persists them through whichever
network management backends are detected on the host so they survive a reboot.

### Logging

The package uses a single, package-wide logger for non-fatal diagnostics from
backends and control panels. It defaults to the logrus standard logger. Replace
it with `SetLogger` before constructing any `Configurator`:

```go
netconfig.SetLogger(myLogger) // anything with Printf/Println, e.g. *log.Logger
```

### Options

`NewConfigurator` accepts functional options:

```go
c, err := netconfig.NewConfigurator(
    netconfig.WithTestAddress("http://my-canary/health"), // connectivity-test URL
    netconfig.WithConnectivityCheck(false),                // skip the post-change probe + rollback
    netconfig.WithSkipConnectivityCheck(),                 // same as WithConnectivityCheck(false)
    netconfig.WithConnectivityTimeout(5 * time.Second),    // HTTP reachability timeout
    netconfig.WithPingCount(3),                            // ICMP probes per ping test
    netconfig.WithPingTimeout(10 * time.Second),           // overall ping-run timeout
    netconfig.WithBackupRetention(10),                     // .bak.* copies kept per config file (0 = keep all)
    netconfig.WithAllowPrimaryRemoval(true),               // let RemoveAddress remove the primary IP
    netconfig.WithSkipPanels(true),                        // skip all panel interaction (add/primary/remove)
)
```

`WithConnectivityCheck(false)` (or the convenience `WithSkipConnectivityCheck()`) is useful on hosts with no outbound internet
access, where the default reachability test would always fail and roll changes
back. `WithConnectivityTimeout`, `WithPingCount`, and `WithPingTimeout` tune the
probes used after gateway changes. `WithBackupRetention` limits how many
`.bak.<timestamp>` copies each backend keeps per original config file; the
oldest backups beyond this number are pruned on every save.

`WithAllowPrimaryRemoval(true)` overrides the default refusal to remove an
address that is the primary of its family. The intended safe flow is to call
`SetPrimaryAddress` on another address first and then remove the old one; enable
the override only when you are deliberately tearing down the current primary.

`WithSkipPanels(true)` skips all control-panel interaction: `AddAddress`,
`SetPrimaryAddress`, and `RemoveAddress` do not tell cPanel, Plesk, or
InterWorx to reload, set the main IP, or release an IP. Only the running system
and the network-manager configuration files are changed.

`FindInterfaceByName` accepts two well-known selectors in addition to a literal
interface name:

- `"public-internet"` — the interface that carries the IPv4 default gateway.
- `"public-internet-6"` — the interface that carries the IPv6 default gateway.

## Usage

```go
package main

import (
    "context"
    "log"
    "net"

    netconfig "github.com/grmrgecko/go-network-configurator"
)

func main() {
    ctx := context.Background()

    c, err := netconfig.NewConfigurator()
    if err != nil {
        log.Fatal(err)
    }

    ifaces, err := c.GetInterfaces(ctx)
    if err != nil {
        log.Fatal(err)
    }
    iface := netconfig.FindInterfaceByName(netconfig.Public, ifaces)
    if iface == nil {
        log.Fatal("no public interface found")
    }

    // Swap the primary IP without dropping connectivity:
    // add a new address, switch the system over to it, then remove the old one.
    _, newIP, _ := net.ParseCIDR("203.0.113.20/24")
    _, oldIP, _ := net.ParseCIDR("203.0.113.10/24")

    if err := c.AddAddress(ctx, iface.Name, newIP, nil); err != nil {
        log.Fatal(err)
    }
    if err := c.SetPrimaryAddress(ctx, iface.Name, newIP); err != nil {
        log.Fatal(err)
    }
    if err := c.RemoveAddress(ctx, iface.Name, oldIP); err != nil {
        log.Fatal(err)
    }
}
```

The primary address is the first address listed on an interface.
`SetPrimaryAddress` reorders an interface's addresses so the chosen IP is
first within its family, both in the running kernel and in the written
configuration. The address must already be present on the interface
(compose it with `AddAddress`); IPv4 and IPv6 each have their own primary.

## Safety

Operations that can break connectivity are guarded:

- Adding an IP that already answers ping is refused.
- After an address/gateway change, an internet-reachability test runs; if it
  fails, the previous runtime state (addresses and default route) is restored
  and the operation returns an error.
- Removing an address that is the only route to the default gateway is refused.
- Removing the primary address of its family is refused by default (use
  `WithAllowPrimaryRemoval(true)` to override). The safe flow is to promote
  another address with `SetPrimaryAddress` first, then remove the old one.

Most operations require elevated privileges (root on Linux, Administrator on
Windows) to modify network state.

## Development

```sh
go test ./...
```

Some tests exercise real kernel networking inside a throwaway network namespace
and are skipped unless run as root:

```sh
sudo go test ./...
```
