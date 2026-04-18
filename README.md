# nc_scan (Python)

A fast concurrent TCP/TLS port scanner using a YAML config file.

## Features

- TCP connect mode (`tls_handshake: false`)
- TCP + TLS handshake mode (`tls_handshake: true`)
- Concurrent scanning (`concurrency` setting)
- Hostname and IPv4 range expansion (`10.0.0.1-10.0.0.20`)
- Optional `open_only` filtering
- Optional output file export
- Optional known subdomain discovery (`find_subdomains`)

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Edit `config.yaml`:

```yaml
ips: 104.19.229.21, 1.1.1.1, hcaptcha.com
ports: 80, 443, 8080, 8443
timeout: 2
concurrency: 200
tls_handshake: true
open_only: false
output_file: results.txt
find_subdomains: false
```

## Usage

```bash
python nc_scan.py
python nc_scan.py --config ./config.yaml
python nc_scan.py -i "hcaptcha.com,1.1.1.1" -p "443,8443" -o out.txt --tls-handshake
python nc_scan.py -i "example.com" -p "443" --find-subdomains
python nc_scan.py --input-file ./targets.txt -p "80,443"
```

`--input-file` accepts a `.txt` file where each line is either:
- a URL (for example `https://example.com/path`) or
- a plain host/IP (for example `example.com` or `1.1.1.1`)

Blank lines and lines starting with `#` are ignored.

### CLI overrides

CLI flags override values from `config.yaml`.

- `-c, --config` path to config file
- `-i, --ips` targets (single/list/range format from config)
- `--input-file` TXT file with one URL/host per line
- `-p, --ports` ports (single/list/range format from config)
- `-t, --timeout` timeout in seconds
- `--open-only` only display/save open results
- `--concurrency` max concurrent probes
- `--tls-handshake` force TLS probe mode
- `--tcp-only` force TCP-only probe mode
- `--find-subdomains` discover known subdomains from crt.sh for each domain target
- `-o, --output` output file path (`""` to disable)

## Output statuses

- `open` — successful probe
- `closed` — connection refused
- `timeout` — timed out
- `tlsfail` — TCP connected, TLS handshake failed
- `error` — other network error

## License

MIT
