#!/usr/bin/env python3
"""nc_scan: TCP/TLS port scanner driven by config.yaml."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


KNOWN_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    587: "SMTP/sub",
    853: "DoT",
    993: "IMAPS",
    995: "POP3S",
    2052: "CF-HTTP",
    2053: "CF-HTTPS",
    2082: "CF-HTTP",
    2083: "CF-HTTPS",
    2086: "CF-HTTP",
    2087: "CF-HTTPS",
    2095: "CF-HTTP",
    2096: "CF-HTTPS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8880: "HTTP-alt",
}


@dataclass(slots=True)
class Config:
    targets: list[str]
    ports: list[int]
    timeout_s: float
    open_only: bool
    output_file: str | None
    concurrency: int
    tls_handshake: bool


@dataclass(slots=True)
class ProbeResult:
    host: str
    port: int
    status: str
    reason: str | None
    latency_ms: int
    resolved_ip: str | None


def parse_csv(raw: Any) -> list[str]:
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def expand_ports(raw: Any) -> list[int]:
    ports: set[int] = set()
    for token in parse_csv(raw):
        if "-" in token:
            start_s, end_s = token.split("-", maxsplit=1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    ports.add(port)
        else:
            port = int(token)
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def expand_ips(raw: Any) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for token in parse_csv(raw):
        if "-" in token and token.count(".") >= 3:
            left, right = token.split("-", maxsplit=1)
            left_octets = left.split(".")
            if len(left_octets) == 4:
                if "." in right:
                    right_octets = right.split(".")
                    if len(right_octets) == 4 and left_octets[:3] == right_octets[:3]:
                        start, end = int(left_octets[3]), int(right_octets[3])
                    else:
                        start = end = None  # type: ignore[assignment]
                else:
                    start, end = int(left_octets[3]), int(right)
                if start is not None and end is not None:
                    if start > end:
                        start, end = end, start
                    prefix = ".".join(left_octets[:3])
                    for i in range(start, end + 1):
                        candidate = f"{prefix}.{i}"
                        if candidate not in seen:
                            seen.add(candidate)
                            targets.append(candidate)
                    continue

        if token not in seen:
            seen.add(token)
            targets.append(token)
    return targets


def is_raw_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_config(config_path: Path) -> Config:
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    raw = parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    if "ips" not in raw or "ports" not in raw:
        raise ValueError("Missing required config keys: ips and ports")

    output_file = str(raw.get("output_file", "")).strip() or None
    return Config(
        targets=expand_ips(raw["ips"]),
        ports=expand_ports(raw["ports"]),
        timeout_s=float(raw.get("timeout", 1)),
        open_only=str(raw.get("open_only", "false")).lower() == "true",
        output_file=output_file,
        concurrency=max(1, int(raw.get("concurrency", 200))),
        tls_handshake=str(raw.get("tls_handshake", "false")).lower() == "true",
    )


def parse_simple_yaml(content: str) -> dict[str, str]:
    """
    Parse simple `key: value` YAML used by this project.

    This intentionally supports only plain top-level scalars.
    """
    data: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", maxsplit=1)
        data[key.strip()] = value.strip()
    return data


def classify(open_ok: bool, reason: str | None, tls_failed: bool) -> str:
    if open_ok:
        return "open"
    if tls_failed:
        return "tlsfail"
    reason = reason or ""
    if reason in {"timeout", "ETIMEDOUT", "DNS timeout"}:
        return "timeout"
    if "ECONNREFUSED" in reason or "Connection refused" in reason:
        return "closed"
    return "error"


def probe_tcp(host: str, port: int, timeout_s: float) -> tuple[bool, str | None, int]:
    t0 = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        return True, None, int((time.perf_counter() - t0) * 1000)
    except socket.timeout:
        return False, "timeout", int((time.perf_counter() - t0) * 1000)
    except OSError as exc:
        return False, exc.strerror or exc.__class__.__name__, int((time.perf_counter() - t0) * 1000)
    finally:
        if sock:
            sock.close()


def resolve_host(host: str) -> list[str]:
    if is_raw_ip(host):
        return [host]
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def probe_tls(host: str, port: int, timeout_s: float) -> tuple[bool, str | None, int, str | None, bool]:
    t0 = time.perf_counter()
    try:
        ips = resolve_host(host)
    except Exception as exc:  # noqa: BLE001
        return False, f"DNS: {exc}", int((time.perf_counter() - t0) * 1000), None, False

    last_reason = "no IPs"
    last_ip: str | None = None

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    for ip in ips:
        last_ip = ip
        try:
            tcp_sock = socket.create_connection((ip, port), timeout=timeout_s)
        except socket.timeout:
            last_reason = "ETIMEDOUT"
            continue
        except OSError as exc:
            last_reason = exc.strerror or exc.__class__.__name__
            continue

        try:
            with tcp_sock:
                with context.wrap_socket(
                    tcp_sock,
                    server_hostname=None if is_raw_ip(host) else host,
                ) as tls_sock:
                    tls_sock.settimeout(timeout_s)
                    tls_sock.do_handshake()
            return True, None, int((time.perf_counter() - t0) * 1000), ip, False
        except ssl.SSLError as exc:
            return False, str(exc), int((time.perf_counter() - t0) * 1000), ip, True
        except socket.timeout:
            return False, "ETIMEDOUT", int((time.perf_counter() - t0) * 1000), ip, True
        except OSError as exc:
            return False, exc.strerror or exc.__class__.__name__, int((time.perf_counter() - t0) * 1000), ip, True

    return False, last_reason, int((time.perf_counter() - t0) * 1000), last_ip, False


def probe(host: str, port: int, cfg: Config) -> ProbeResult:
    if cfg.tls_handshake:
        open_ok, reason, latency_ms, resolved_ip, tls_failed = probe_tls(host, port, cfg.timeout_s)
    else:
        open_ok, reason, latency_ms = probe_tcp(host, port, cfg.timeout_s)
        resolved_ip = host if is_raw_ip(host) else None
        tls_failed = False

    return ProbeResult(
        host=host,
        port=port,
        status=classify(open_ok, reason, tls_failed),
        reason=reason,
        latency_ms=latency_ms,
        resolved_ip=resolved_ip,
    )


async def run_scan(cfg: Config) -> list[ProbeResult]:
    semaphore = asyncio.Semaphore(cfg.concurrency)
    targets = [(host, port) for host in cfg.targets for port in cfg.ports]

    async def one(host: str, port: int) -> ProbeResult:
        async with semaphore:
            return await asyncio.to_thread(probe, host, port, cfg)

    return await asyncio.gather(*(one(h, p) for h, p in targets))


def display(results: list[ProbeResult], cfg: Config) -> None:
    mode = "TCP+TLS" if cfg.tls_handshake else "TCP only"
    print(f"\nnc_scan results ({mode})")
    print("=" * 98)
    if cfg.tls_handshake:
        print(f"{'STATUS':8} {'HOST':28} {'RESOLVED IP':16} {'PORT':>5} {'SERVICE':12} {'LATENCY':>8}")
    else:
        print(f"{'STATUS':8} {'HOST':28} {'PORT':>5} {'SERVICE':12} {'LATENCY':>8}")

    filtered = [r for r in results if not cfg.open_only or r.status == "open"]
    for r in filtered:
        service = KNOWN_PORTS.get(r.port, "")
        latency = f"{r.latency_ms}ms"
        if cfg.tls_handshake:
            print(f"{r.status:8} {r.host:28} {(r.resolved_ip or '—'):16} {r.port:5} {service:12} {latency:>8}")
        else:
            print(f"{r.status:8} {r.host:28} {r.port:5} {service:12} {latency:>8}")

    open_count = sum(1 for r in results if r.status == "open")
    print("-" * 98)
    print(f"Open ports: {open_count}/{len(results)}")


def save_results(results: list[ProbeResult], cfg: Config) -> None:
    if not cfg.output_file:
        return
    out = Path(cfg.output_file)
    lines = [
        f"# nc_scan results — {datetime.now(timezone.utc).isoformat()}",
        f"# mode: {'TCP+TLS' if cfg.tls_handshake else 'TCP only'}",
        "",
    ]
    for r in results:
        if cfg.open_only and r.status != "open":
            continue
        lines.append(
            f"{r.status:8} {r.host:28} {(r.resolved_ip or '—'):16} :{r.port:5}  "
            f"{KNOWN_PORTS.get(r.port, ''):12} {r.latency_ms}ms"
        )
    lines.append("")
    open_count = sum(1 for r in results if r.status == "open")
    lines.append(f"# {open_count} open / {len(results)} total")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def async_main() -> int:
    parser = argparse.ArgumentParser(description="nc_scan (Python)")
    parser.add_argument("--config", default="config.yaml", help="Path to config yaml file")
    args = parser.parse_args()

    cfg = load_config(Path(args.config).resolve())
    started = time.perf_counter()
    results = await run_scan(cfg)
    elapsed_s = time.perf_counter() - started

    display(results, cfg)
    save_results(results, cfg)
    print(f"Elapsed: {elapsed_s:.2f}s")
    return 0


def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
