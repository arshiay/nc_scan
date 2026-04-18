# nc_scan (Python)

A fast concurrent TCP/TLS port scanner using a YAML config file.

## Features

- TCP connect mode (`tls_handshake: false`)
- TCP + TLS handshake mode (`tls_handshake: true`)
- Concurrent scanning (`concurrency` setting)
- Hostname and IPv4 range expansion (`10.0.0.1-10.0.0.20`)
- Optional `open_only` filtering
- Optional output file export

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
```

## Usage

```bash
python nc_scan.py
python nc_scan.py --config ./config.yaml
```

## Output statuses

- `open` — successful probe
- `closed` — connection refused
- `timeout` — timed out
- `tlsfail` — TCP connected, TLS handshake failed
- `error` — other network error

## License

MIT
