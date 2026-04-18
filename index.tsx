#!/usr/bin/env bun
/**
 * NC Scanner
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import { parse } from "yaml";
import { resolve } from "path";
import * as tlsModule from "tls";
import * as netModule from "net";
import * as dnsModule from "dns/promises";
import React, { useState, useEffect, useCallback, useRef } from "react";
import { render, Box, Text, useApp, useInput, useStdout } from "ink";

// ── Types ──────────────────────────────────────────────────────────────────

interface Config {
  targets: string[];
  ports: number[];
  timeoutMs: number;
  openOnly: boolean;
  outputFile: string | null;
  concurrency: number;
  tlsHandshake: boolean;
}

// "tlsfail" = TCP connected but TLS handshake was rejected
type Status = "pending" | "scanning" | "open" | "closed" | "timeout" | "tlsfail" | "error";

interface ProbeEntry {
  id: string;
  host: string;
  port: number;
  status: Status;
  reason?: string;
  latencyMs?: number;
  lastScanned?: Date;
  retries: number;
  resolvedIP?: string;
}

// ── Known ports ────────────────────────────────────────────────────────────

const KNOWN_PORTS: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
  587: "SMTP/sub", 853: "DoT", 993: "IMAPS", 995: "POP3S",
  2052: "CF-HTTP", 2053: "CF-HTTPS", 2082: "CF-HTTP",
  2083: "CF-HTTPS", 2086: "CF-HTTP", 2087: "CF-HTTPS",
  2095: "CF-HTTP", 2096: "CF-HTTPS",
  8080: "HTTP-alt", 8443: "HTTPS-alt", 8880: "HTTP-alt",
};

// ── Config ─────────────────────────────────────────────────────────────────

function parseCSV(raw: string | number): string[] {
  return String(raw).split(",").map(s => s.trim()).filter(Boolean);
}

function expandPorts(raw: string | number): number[] {
  const ports: number[] = [];
  for (const token of parseCSV(raw)) {
    if (token.includes("-")) {
      const [a, b] = token.split("-").map(Number);
      for (let p = a ?? 0; p <= (b ?? 0); p++) ports.push(p);
    } else {
      const n = parseInt(token, 10);
      if (!isNaN(n)) ports.push(n);
    }
  }
  return [...new Set(ports)].sort((a, b) => a - b);
}

function expandIPs(raw: string | number): string[] {
  const targets: string[] = [];
  for (const token of parseCSV(raw)) {
    const m = token.match(/^(\d+\.\d+\.\d+\.)(\d+)-(?:\d+\.\d+\.\d+\.)?(\d+)$/);
    if (m) {
      for (let i = parseInt(m[2] ?? "0"); i <= parseInt(m[3] ?? "0"); i++)
        targets.push(`${m[1]}${i}`);
    } else {
      targets.push(token);
    }
  }
  return [...new Set(targets)];
}

function loadConfig(configPath: string): Config {
  if (!existsSync(configPath)) {
    console.error(`Config not found: ${configPath}`); process.exit(1);
  }
  const raw = parse(readFileSync(configPath, "utf8")) as any;
  if (!raw.ips || !raw.ports) { console.error("Missing ips/ports in config"); process.exit(1); }
  return {
    targets: expandIPs(raw.ips),
    ports: expandPorts(raw.ports),
    timeoutMs: Math.round(parseFloat(String(raw.timeout ?? 1)) * 1000),
    openOnly: String(raw.open_only) === "true",
    outputFile: raw.output_file?.trim() || null,
    concurrency: parseInt(String(raw.concurrency ?? 200), 10),
    // tls_handshake: true  → TCP + TLS
    // tls_handshake: false → TCP only
    tlsHandshake: String(raw.tls_handshake ?? "false") === "true",
  };
}

// ── TCP-only probe ─────────────────────────
//
// Bun.connect() fires open() BEFORE the promise resolves, so we use the
// socket argument `s` directly in open() and clean up dangling sockets
// in the .then() branch for the timeout-race case.

async function probeTCP(
  host: string,
  port: number,
  timeoutMs: number
): Promise<{ open: boolean; reason?: string; latencyMs: number }> {
  const t0 = Date.now();
  return new Promise((promiseResolve) => {
    let resolved = false;

    const done = (open: boolean, reason?: string) => {
      if (resolved) return;
      resolved = true;
      promiseResolve({ open, reason, latencyMs: Date.now() - t0 });
    };

    const timer = setTimeout(() => done(false, "timeout"), timeoutMs);

    Bun.connect({
      hostname: host,
      port,
      socket: {
        open(s: any) {
          clearTimeout(timer);
          done(true);
          s.end();
        },
        error(_s: any, e: any) {
          clearTimeout(timer);
          done(false, (e as NodeJS.ErrnoException)?.code ?? "error");
        },
        connectError(_s: any, e: any) {
          clearTimeout(timer);
          done(false, (e as NodeJS.ErrnoException)?.code ?? "ECONNREFUSED");
        },
        close() { }, data() { },
      },
    })
      .then((s) => { if (resolved) { try { s.end(); } catch { } } })
      .catch((e: any) => {
        clearTimeout(timer);
        done(false, (e as NodeJS.ErrnoException)?.code ?? String(e));
      });
  });
}

// ── TCP + TLS probe (dial → handshake) ─────────────────
//
// 1. DNS resolve (skip if already an IP)
// 2. TCP connect via node:net (gives us a raw socket we can wrap)
// 3. TLS handshake via node:tls wrapping that socket
//    InsecureSkipVerify: true  — we don't care about cert validity,
//    just whether the server accepts the connection.
// 4. Returns resolvedIP so the UI can display it.

function isRawIP(str: string): boolean {
  return netModule.isIP(str) !== 0;
}

async function resolveHost(host: string, timeoutMs: number): Promise<string[]> {
  if (isRawIP(host)) return [host];
  return new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error("DNS timeout")), timeoutMs);
    dnsModule.lookup(host, { all: true })
      .then(addrs => { clearTimeout(t); res(addrs.map(a => a.address)); })
      .catch(e => { clearTimeout(t); rej(e); });
  });
}

function tcpDial(ip: string, port: number, timeoutMs: number): Promise<netModule.Socket> {
  return new Promise((res, rej) => {
    const sock = new netModule.Socket();
    const t = setTimeout(() => {
      sock.destroy();
      rej(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }));
    }, timeoutMs);
    sock.connect(port, ip, () => { clearTimeout(t); res(sock); });
    sock.once("error", e => { clearTimeout(t); sock.destroy(); rej(e); });
  });
}

function tlsDial(
  sock: netModule.Socket,
  serverName: string,
  timeoutMs: number
): Promise<void> {
  return new Promise((res, rej) => {
    const tSock = new tlsModule.TLSSocket(sock, {
      rejectUnauthorized: false,        // InsecureSkipVerify: true
      serverName: isRawIP(serverName) ? undefined : serverName,
      minVersion: "TLSv1.2",
    });
    const t = setTimeout(() => { tSock.destroy(); rej(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })); }, timeoutMs);
    tSock.once("secureConnect", () => { clearTimeout(t); tSock.destroy(); res(); });
    tSock.once("error", e => { clearTimeout(t); tSock.destroy(); rej(e); });
  });
}

async function probeTLS(
  host: string,
  port: number,
  timeoutMs: number
): Promise<{ open: boolean; reason?: string; latencyMs: number; resolvedIP?: string; tlsFailed?: boolean }> {
  const t0 = Date.now();

  // DNS
  let ips: string[];
  try {
    ips = await resolveHost(host, timeoutMs);
  } catch (e: any) {
    return { open: false, reason: `DNS: ${e.message ?? e}`, latencyMs: Date.now() - t0 };
  }

  let lastReason = "no IPs";
  let lastIP = "?";

  for (const ip of ips) {
    lastIP = ip;
    let sock: netModule.Socket | null = null;
    try {
      sock = await tcpDial(ip, port, timeoutMs);
    } catch (e: any) {
      lastReason = (e as NodeJS.ErrnoException).code ?? e.message;
      continue; // try next IP
    }

    // TCP succeeded — attempt TLS
    try {
      await tlsDial(sock, host, timeoutMs);
      return { open: true, latencyMs: Date.now() - t0, resolvedIP: ip };
    } catch (e: any) {
      sock.destroy();
      // TCP open but TLS rejected — report as tlsfail (not "closed")
      return {
        open: false,
        latencyMs: Date.now() - t0,
        resolvedIP: ip,
        reason: (e as NodeJS.ErrnoException).code ?? e.message,
        tlsFailed: true,
      };
    }
  }

  return { open: false, reason: lastReason, latencyMs: Date.now() - t0, resolvedIP: lastIP };
}

// ── Unified probe dispatcher ───────────────────────────────────────────────

type ProbeResult = {
  open: boolean;
  reason?: string;
  latencyMs: number;
  resolvedIP?: string;
  tlsFailed?: boolean;
};

async function probePort(
  host: string,
  port: number,
  timeoutMs: number,
  useTLS: boolean
): Promise<ProbeResult> {
  if (useTLS) return probeTLS(host, port, timeoutMs);
  const r = await probeTCP(host, port, timeoutMs);
  return { ...r, resolvedIP: isRawIP(host) ? host : undefined };
}

// ── Classify ───────────────────────────────────────────────────────────────

function classify(r: ProbeResult): Status {
  if (r.open) return "open";
  if (r.tlsFailed) return "tlsfail";
  const c = r.reason ?? "";
  if (c === "timeout" || c === "ETIMEDOUT" || c === "DNS timeout") return "timeout";
  if (c === "ECONNREFUSED" || c.includes("ECONNREFUSED")) return "closed";
  return "error";
}

// ── Scan helpers ───────────────────────────────────────────────────────────

async function scanEntry(
  entry: ProbeEntry,
  cfg: Config,
  onUpdate: (id: string, patch: Partial<ProbeEntry>) => void
): Promise<void> {
  onUpdate(entry.id, { status: "scanning" });
  const result = await probePort(entry.host, entry.port, cfg.timeoutMs, cfg.tlsHandshake);
  onUpdate(entry.id, {
    status: classify(result),
    reason: result.reason,
    latencyMs: result.latencyMs || undefined,
    resolvedIP: result.resolvedIP,
    lastScanned: new Date(),
    retries: entry.retries + (entry.status !== "pending" ? 1 : 0),
  });
}

async function runScan(
  entries: ProbeEntry[],
  cfg: Config,
  onUpdate: (id: string, patch: Partial<ProbeEntry>) => void
): Promise<void> {
  let idx = 0;
  async function worker() {
    while (idx < entries.length) {
      const entry = entries[idx++];
      if (entry) await scanEntry(entry, cfg, onUpdate);
    }
  }
  await Promise.all(Array.from({ length: Math.min(cfg.concurrency, entries.length) }, worker));
}

// ── Copy to clipboard ──────────────────────────────────────────────────────

async function copyToClipboard(text: string): Promise<boolean> {
  const cmds: string[][] = [
    ["pbcopy"], ["xclip", "-selection", "clipboard"],
    ["xsel", "--clipboard", "--input"], ["wl-copy"],
  ];
  for (const [cmd, ...args] of cmds) {
    if (!cmd) continue;
    try {
      const proc = Bun.spawn([cmd, ...args], { stdin: "pipe" });
      proc.stdin.write(text); proc.stdin.end();
      await proc.exited;
      if (proc.exitCode === 0) return true;
    } catch { }
  }
  return false;
}

// ── Save results ───────────────────────────────────────────────────────────

function saveResults(entries: ProbeEntry[], cfg: Config): void {
  if (!cfg.outputFile) return;
  const lines = [
    `# nc_scan results — ${new Date().toISOString()}`,
    `# mode: ${cfg.tlsHandshake ? "TCP+TLS" : "TCP only"}`,
    "",
    ...entries
      .filter(e => !cfg.openOnly || e.status === "open")
      .map(e =>
        `${e.status.padEnd(8)} ${e.host.padEnd(28)} ${(e.resolvedIP ?? "—").padEnd(16)} :${String(e.port).padStart(5)}  ` +
        `${(KNOWN_PORTS[e.port] ?? "").padEnd(12)} ${e.latencyMs != null ? e.latencyMs + "ms" : "—"}`
      ),
    "",
    `# ${entries.filter(e => e.status === "open").length} open / ${entries.length} total`,
  ];
  writeFileSync(resolve(process.cwd(), cfg.outputFile), lines.join("\n") + "\n");
}

// ══ Ink TUI ════════════════════════════════════════════════════════════════

const STATUS_ICON: Record<Status, string> = {
  pending: "·",
  scanning: "◌",
  open: "●",
  closed: "○",
  timeout: "◎",
  tlsfail: "◑",   // half-filled: TCP ok, TLS blocked
  error: "✕",
};

const STATUS_COLOR: Record<Status, string> = {
  pending: "gray",
  scanning: "yellow",
  open: "green",
  closed: "red",
  timeout: "magenta",
  tlsfail: "yellow",
  error: "redBright",
};

type View = "all" | "open" | "closed";
type SortKey = "host" | "port" | "status" | "latency";

interface Toast { msg: string; color: string; }

const HELP_LINES = [
  "  ↑/↓  k/j     navigate rows",
  "  Enter         re-scan selected row",
  "  r             re-scan ALL rows",
  "  c             copy selected row to clipboard",
  "  C             copy ALL open ports as CSV",
  "  w             save results to output_file",
  "  t             toggle probe mode: TCP only ↔ TCP + TLS handshake",
  "  f             cycle filter:  all → open → closed",
  "  s             cycle sort:    host → port → status → latency",
  "  ?             toggle this help",
  "  q / Esc       quit",
];

const App: React.FC<{ cfg: Config; configPath: string }> = ({
  cfg: initialCfg,
  configPath,
}) => {
  const { exit } = useApp();
  const { stdout } = useStdout();

  // cfg is mutable at runtime (toggling TLS mode)
  const [cfg, setCfg] = useState(initialCfg);

  const mkEntries = (c: Config): ProbeEntry[] => {
    const list: ProbeEntry[] = [];
    for (const host of c.targets)
      for (const port of c.ports)
        list.push({ id: `${host}:${port}`, host, port, status: "pending", retries: 0 });
    return list;
  };

  const [entries, setEntries] = useState<ProbeEntry[]>(() => mkEntries(initialCfg));
  const [cursor, setCursor] = useState(0);
  const [view, setView] = useState<View>("all");
  const [sort, setSort] = useState<SortKey>("host");
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState<Toast | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const [showHelp, setShowHelp] = useState(false);
  const [termSize, setTermSize] = useState({
    rows: stdout.rows || 24,
    cols: stdout.columns || 80,
  });

  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const onResize = () => setTermSize({ rows: stdout.rows, cols: stdout.columns });
    stdout.on("resize", onResize);
    return () => { stdout.off("resize", onResize); };
  }, [stdout]);

  const showToast = useCallback((msg: string, color = "cyan") => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setToast({ msg, color });
    toastTimer.current = setTimeout(() => setToast(null), 2500);
  }, []);

  const patchEntry = useCallback((id: string, patch: Partial<ProbeEntry>) => {
    setEntries(prev => prev.map(e => e.id === id ? { ...e, ...patch } : e));
  }, []);

  const doScan = useCallback(async (targets: ProbeEntry[], scanCfg: Config) => {
    if (scanning) return;
    setScanning(true);
    const t0 = Date.now();
    timerRef.current = setInterval(
      () => setElapsed((Date.now() - t0) / 1000), 100
    );
    await runScan(targets, scanCfg, patchEntry);
    clearInterval(timerRef.current!);
    setScanning(false);
    showToast(
      `Scan complete — ${targets.length} probes  [${scanCfg.tlsHandshake ? "TCP+TLS" : "TCP only"}]`,
      "green"
    );
  }, [scanning, patchEntry, showToast]);

  // Auto-start
  useEffect(() => { doScan(mkEntries(initialCfg), initialCfg); }, []);

  // ── Sort + filter ──────────────────────────────────────────────────────
  const sorted = [...entries].sort((a, b) => {
    if (sort === "host") return a.host.localeCompare(b.host) || a.port - b.port;
    if (sort === "port") return a.port - b.port || a.host.localeCompare(b.host);
    if (sort === "status") return a.status.localeCompare(b.status);
    if (sort === "latency") return (a.latencyMs ?? 99999) - (b.latencyMs ?? 99999);
    return 0;
  });

  const visible = sorted.filter(e => {
    if (view === "open") return e.status === "open";
    if (view === "closed") return ["closed", "timeout", "tlsfail", "error"].includes(e.status);
    return true;
  });

  const safeIdx = Math.min(cursor, Math.max(0, visible.length - 1));
  const selected = visible[safeIdx];

  // ── Input ──────────────────────────────────────────────────────────────
  useInput((input, key) => {
    if (key.upArrow || input === "k") setCursor(c => Math.max(0, c - 1));
    if (key.downArrow || input === "j") setCursor(c => Math.min(visible.length - 1, c + 1));

    if (key.return && selected && !scanning) {
      const fresh = { ...selected, status: "pending" as Status };
      patchEntry(selected.id, { status: "pending" });
      showToast(`Re-scanning ${selected.host}:${selected.port}…`, "yellow");
      scanEntry(fresh, cfg, patchEntry);
    }

    if (input === "r" && !scanning) {
      const fresh = entries.map(e => ({ ...e, status: "pending" as Status }));
      setEntries(fresh);
      setTimeout(() => doScan(fresh, cfg), 10);
    }

    // ── t: toggle TCP-only ↔ TCP+TLS ──────────────────────────────────
    if (input === "t") {
      const next = { ...cfg, tlsHandshake: !cfg.tlsHandshake };
      setCfg(next);
      showToast(
        next.tlsHandshake
          ? "Mode: TCP + TLS handshake"
          : "Mode: TCP only  (fast connect check)",
        "cyan"
      );
    }

    if (input === "c" && selected) {
      const svc = KNOWN_PORTS[selected.port] ?? "";
      const text = [
        `${selected.host}:${selected.port}`,
        selected.resolvedIP ?? "",
        selected.status,
        selected.latencyMs != null ? `${selected.latencyMs}ms` : "",
        svc,
      ].filter(Boolean).join("  ");
      copyToClipboard(text).then(ok =>
        showToast(ok ? `Copied: ${text}` : "Clipboard unavailable", ok ? "green" : "red")
      );
    }

    if (input === "C") {
      const open = entries.filter(e => e.status === "open");
      if (!open.length) { showToast("No open ports found", "red"); return; }
      const csv = [
        "host,resolved_ip,port,service,latency_ms",
        ...open.map(e =>
          `${e.host},${e.resolvedIP ?? ""},${e.port},${KNOWN_PORTS[e.port] ?? ""},${e.latencyMs ?? ""}`
        ),
      ].join("\n");
      copyToClipboard(csv).then(ok =>
        showToast(
          ok ? `Copied ${open.length} open port${open.length !== 1 ? "s" : ""} as CSV`
            : "Clipboard unavailable",
          ok ? "green" : "red"
        )
      );
    }

    if (input === "w") {
      saveResults(entries, cfg);
      showToast(
        cfg.outputFile ? `Saved → ${cfg.outputFile}` : "No output_file in config",
        cfg.outputFile ? "green" : "red"
      );
    }

    if (input === "f") {
      const cycle: View[] = ["all", "open", "closed"];
      setView(v => cycle[(cycle.indexOf(v) + 1) % cycle.length]!);
      setCursor(0);
    }

    if (input === "s") {
      const cycle: SortKey[] = ["host", "port", "status", "latency"];
      setSort(s => cycle[(cycle.indexOf(s) + 1) % cycle.length]!);
    }

    if (input === "?") setShowHelp(v => !v);

    if (input === "q" || key.escape) {
      process.stdout.write("\x1b[?1049l\x1b[?25h");
      exit();
    }
  });

  // ── Stats ──────────────────────────────────────────────────────────────
  const total = entries.length;
  const nOpen = entries.filter(e => e.status === "open").length;
  const nClosed = entries.filter(e => ["closed", "timeout", "tlsfail", "error"].includes(e.status)).length;
  const nPend = entries.filter(e => ["pending", "scanning"].includes(e.status)).length;
  const pct = total > 0 ? Math.floor(((total - nPend) / total) * 100) : 100;

  const BAR_W = 20;
  const filled = Math.round((pct / 100) * BAR_W);
  const bar = "▰".repeat(filled) + "▱".repeat(BAR_W - filled);

  // ── Viewport ───────────────────────────────────────────────────────────
  const { rows, cols } = termSize;
  const HEADER = showHelp ? 4 + HELP_LINES.length : 4;
  const FOOTER = 4;
  const VIEW_H = Math.max(1, rows - HEADER - FOOTER);

  let vpStart = Math.max(0, safeIdx - Math.floor(VIEW_H / 2));
  if (vpStart + VIEW_H > visible.length) vpStart = Math.max(0, visible.length - VIEW_H);
  const page = visible.slice(vpStart, vpStart + VIEW_H);
  const div = "─".repeat(Math.max(0, cols - 2));

  // Mode badge shown in banner
  const modeBadge = cfg.tlsHandshake ? "TCP+TLS" : "TCP";

  return (
    <Box width={cols} flexDirection="column">

      {/* ── Banner ── */}
      <Box>
        <Text color="cyan" bold>▌</Text>
        <Text color="white" bold> NC_SCAN </Text>
        <Text color="cyan" bold>▐</Text>
        <Text dimColor>NC Scanner By Rend</Text>
        <Text color={cfg.tlsHandshake ? "green" : "yellow"} bold>{modeBadge}</Text>
        <Text dimColor>  ·  {configPath}  </Text>
        <Text color="cyan" dimColor>? help</Text>
      </Box>

      {/* ── Optional help panel ── */}
      {showHelp && (
        <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1} marginY={0}>
          {HELP_LINES.map((l, i) => <Text key={i} dimColor>{l}</Text>)}
        </Box>
      )}

      <Text dimColor>{div}</Text>

      {/* ── Column headers ── */}
      <Box>
        <Text bold color="gray">{"    ST  "}</Text>
        <Text bold color="gray">{"HOST                        "}</Text>
        {cfg.tlsHandshake && <Text bold color="gray">{"RESOLVED IP      "}</Text>}
        <Text bold color="gray">{"PORT   "}</Text>
        <Text bold color="gray">{"SERVICE      "}</Text>
        <Text bold color="gray">{"LATENCY  "}</Text>
        <Text bold color="gray">{"RTY  "}</Text>
        <Text bold color="gray">{"SCANNED"}</Text>
      </Box>
      <Text dimColor>{div}</Text>

      {/* ── Rows ── */}
      {page.map((entry, i) => {
        const absIdx = vpStart + i;
        const isSel = absIdx === safeIdx;
        const svc = KNOWN_PORTS[entry.port] ?? "—";
        const lat = entry.latencyMs != null ? `${entry.latencyMs}ms` : "—";
        const ts = entry.lastScanned
          ? entry.lastScanned.toTimeString().slice(0, 8) : "—";
        const icon = STATUS_ICON[entry.status];
        const color = STATUS_COLOR[entry.status] as any;

        return (
          <Box key={entry.id}>
            <Text color={isSel ? "cyan" : "gray"}>{isSel ? " ▶" : "  "}</Text>
            <Text color={color} bold={isSel}>{` ${icon}  `}</Text>
            <Text color={isSel ? "white" : "gray"} bold={isSel}>
              {entry.host.padEnd(28)}
            </Text>
            {cfg.tlsHandshake && (
              <Text color={isSel ? "cyan" : "gray"} dimColor={!isSel}>
                {(entry.resolvedIP ?? "—").padEnd(17)}
              </Text>
            )}
            <Text color={isSel ? "cyan" : "gray"} bold={isSel}>
              {String(entry.port).padStart(5) + "  "}
            </Text>
            <Text color={isSel ? "white" : "gray"} dimColor={!isSel}>
              {svc.padEnd(13)}
            </Text>
            <Text color={isSel ? "yellow" : "gray"} dimColor={!isSel}>
              {lat.padEnd(9)}
            </Text>
            <Text dimColor>{String(entry.retries || 0).padEnd(5)}</Text>
            <Text dimColor>{ts}</Text>
          </Box>
        );
      })}

      {/* ── Empty rows filler ── */}
      {Array.from({ length: Math.max(0, VIEW_H - page.length) }).map((_, i) => (
        <Box key={`pad-${i}`}><Text>{" "}</Text></Box>
      ))}

      {/* ── Footer ── */}
      <Text dimColor>{div}</Text>

      {/* ── Stats + progress ── */}
      <Box>
        <Text color="green" bold>  ● {nOpen}</Text>
        <Text dimColor> open  </Text>
        <Text color="red">○ {nClosed}</Text>
        <Text dimColor> closed  </Text>
        <Text color="yellow">◌ {nPend}</Text>
        <Text dimColor> pending  /  {total} total    </Text>
        {scanning
          ? <><Text color="yellow">[{bar}] </Text><Text bold>{pct}%  </Text><Text dimColor>{elapsed.toFixed(1)}s</Text></>
          : <Text color="green">✔ done  {elapsed.toFixed(1)}s</Text>
        }
        <Text dimColor>   sort:{sort}  view:{view}</Text>
        {visible.length > VIEW_H && (
          <Text dimColor>   row {safeIdx + 1}/{visible.length}</Text>
        )}
      </Box>

      {/* ── Keybind strip ── */}
      <Box>
        <Text dimColor>  </Text>
        {[
          ["Enter", "retry"], ["r", "all"], ["c", "copy"], ["C", "CSV"],
          ["w", "save"], ["t", cfg.tlsHandshake ? "→TCP" : "→TLS"],
          ["f", "filter"], ["s", "sort"], ["q", "quit"], ["?", "help"],
        ].map(([k, label]) => (
          <React.Fragment key={k}>
            <Text color={k === "t" ? (cfg.tlsHandshake ? "green" : "yellow") : "cyan"}>{k}</Text>
            <Text dimColor>{` ${label}  `}</Text>
          </React.Fragment>
        ))}
      </Box>

      {/* ── Toast ── */}
      <Box height={1}>
        {toast
          ? <Text color={toast.color as any} bold>  ⚡ {toast.msg}</Text>
          : <Text> </Text>
        }
      </Box>

    </Box>
  );
};

// ── Entry point ────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const cfgIdx = args.indexOf("--config");
const configPath = cfgIdx !== -1 && args[cfgIdx + 1]
  ? resolve(args[cfgIdx + 1]!)
  : resolve(process.cwd(), "config.yaml");

const cfg = loadConfig(configPath);

process.stdout.write("\x1b[?1049h\x1b[?25l");
const cleanup = () => process.stdout.write("\x1b[?1049l\x1b[?25h");
process.on("exit", cleanup);
process.on("SIGINT", () => { cleanup(); process.exit(0); });
process.on("SIGTERM", () => { cleanup(); process.exit(0); });

render(<App cfg={cfg} configPath={configPath} />, { exitOnCtrlC: false });
