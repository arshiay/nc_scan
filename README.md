# ncscan


## Features

- **TCP connect** and **TCP + TLS handshake** probe modes (toggle with `t`)
- Concurrent scanning with configurable concurrency
- Interactive TUI: navigate, re-scan, filter, sort, copy results
- YAML config file (`nc_scan.yaml`)
- Cross-platform: macOS, Linux, Windows

## Install

Download the latest binary for your platform from [Releases](../../releases).

| Platform       | File                        |
|----------------|-----------------------------|
| macOS ARM64    | `ncscan_darwin_arm64`       |
| macOS x64      | `ncscan_darwin_x64`         |
| Linux ARM64    | `ncscan_linux_arm64`        |
| Linux x64      | `ncscan_linux_x64`          |
| Windows ARM64  | `ncscan_windows_arm64.exe`  |
| Windows x64    | `ncscan_windows_x64.exe`    |

Make it executable (macOS/Linux):

```bash
chmod +x ncscan_darwin_arm64
./ncscan_darwin_arm64
```

## Configuration

Create `config.yaml` in the same directory as the binary:

```yaml
# IPs, ranges, or hostnames (comma-separated)
ips: 104.19.229.21, 1.1.1.1, hcaptcha.com, npmjs.com

# Ports — single, list, or range (80-90)
ports: 80, 443, 8080, 8443, 2053, 2083, 2087

# Timeout per connection attempt (seconds)
timeout: 2

# true  = TCP + TLS handshake (accurate, slower)
# false = TCP connect only (fast, like nc -zv)
tls_handshake: false

# Hide closed/timeout ports
open_only: false

# Save results here (leave empty to skip)
output_file: results.txt
```

## Usage

```bash
# Uses config.yaml in the current directory
./ncscan

# Custom config path
./ncscan --config /path/to/config.yaml
```

## Keybindings

| Key     | Action                        |
|---------|-------------------------------|
| `↑` `↓` / `k` `j` | Navigate rows        |
| `Enter` | Re-scan selected row          |
| `r`     | Re-scan all rows              |
| `t`     | Toggle TCP / TCP+TLS mode     |
| `c`     | Copy selected row             |
| `C`     | Copy all open ports as CSV    |
| `w`     | Save results to `output_file` |
| `f`     | Cycle filter: all→open→closed |
| `s`     | Cycle sort: host/port/status/latency |
| `?`     | Toggle help panel             |
| `q`     | Quit                          |

## Build from source

Requires [Bun](https://bun.sh) v1.0+.

```bash
bun install
bun run dev              # run in development
bun run build:all        # build all platforms
```

## License

MIT
