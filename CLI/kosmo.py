#!/usr/bin/env python3
"""
=============================================================================
KOSMO CLI — Universal Log Processing Framework Terminal Client
=============================================================================
Implementation of the official Kosmoporos Terminal Command Line Tool:
  - kosmo connect <url>
  - kosmo send
  - kosmo send all
  - kosmo send <path>
  - kosmo send -n <number>
  - kosmo send <path> -n <number>
  - kosmo report
  - kosmo report save
  - kosmo report save <directory_path>
  - kosmo --help
=============================================================================
"""

import sys
import os
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Configuration and State Files
CLI_DIR = Path(__file__).resolve().parent
CONFIG_FILE = CLI_DIR / ".kosmo_config.json"
STATE_FILE = CLI_DIR / ".kosmo_state.json"
DEFAULT_SERVER_URL = "http://localhost:8000"

# ANSI Terminal Styling
USE_COLOR = sys.stdout.isatty() and (os.name != "nt" or "ANSICON" in os.environ or "WT_SESSION" in os.environ)

def _c(t: str, code: str) -> str:
    return f"\033[{code}m{t}\033[0m" if USE_COLOR else t

def c_bold(t: str) -> str: return _c(t, "1")
def c_green(t: str) -> str: return _c(t, "32")
def c_cyan(t: str) -> str: return _c(t, "36")
def c_yellow(t: str) -> str: return _c(t, "33")
def c_red(t: str) -> str: return _c(t, "31")
def c_dim(t: str) -> str: return _c(t, "2")


# ---------------------------------------------------------------------------
# Configuration Helpers
# ---------------------------------------------------------------------------

def load_config() -> Dict[str, Any]:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"server_url": DEFAULT_SERVER_URL}


def save_config(cfg: Dict[str, Any]) -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save config: {e}", file=sys.stderr)


def get_server_url() -> str:
    cfg = load_config()
    return cfg.get("server_url", DEFAULT_SERVER_URL).rstrip("/")


def normalize_url(url: str) -> str:
    clean = url.strip()
    if not clean.startswith("http://") and not clean.startswith("https://"):
        clean = "http://" + clean
    return clean.rstrip("/")


def load_state() -> Dict[str, Any]:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state(state: Dict[str, Any]) -> None:
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTTP Communication Helpers
# ---------------------------------------------------------------------------

def http_get(url: str, timeout: float = 4.0) -> Tuple[int, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "Kosmo-CLI/1.0", "Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(content)
            except Exception:
                return resp.status, content
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(err)
        except Exception:
            return e.code, err
    except Exception as e:
        return 0, str(e)


def http_post(url: str, data: Any, timeout: float = 10.0) -> Tuple[int, Any]:
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"User-Agent": "Kosmo-CLI/1.0", "Content-Type": "application/json", "Accept": "application/json"},
        method="POST"
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(content)
            except Exception:
                return resp.status, content
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(err)
        except Exception:
            return e.code, err
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# File & Log Discovery
# ---------------------------------------------------------------------------

EXCLUDED_EXTS = {".py", ".pyc", ".git", ".exe", ".bat", ".ps1", ".db", ".png", ".jpg", ".jpeg", ".ico"}
EXCLUDED_NAMES = {"cli commands.txt", ".kosmo_config.json", ".kosmo_state.json", "requirements.txt", "package.json"}

def is_log_candidate(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() in EXCLUDED_EXTS:
        return False
    if path.name.lower() in EXCLUDED_NAMES:
        return False
    # If size is 0 or above 100MB, skip
    try:
        sz = path.stat().st_size
        return 0 < sz < 104857600
    except OSError:
        return False


def get_log_files_in_directory(dir_path: Path) -> List[Path]:
    """Find all potential log files in a directory, ordered by date & time modified (newest first)."""
    candidates = []
    try:
        for item in dir_path.iterdir():
            if is_log_candidate(item):
                candidates.append(item)
    except Exception:
        pass

    # Order as per date and time modified (newest first)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates


def read_logs_from_file(file_path: Path, max_count: Optional[int] = None) -> List[str]:
    """Read log lines from a file."""
    lines = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                l = line.strip()
                if l and not l.startswith("#"):
                    lines.append(l)
                    if max_count and len(lines) >= max_count:
                        break
    except Exception as e:
        print(f"Warning: Could not read '{file_path}': {e}", file=sys.stderr)
    return lines


# ---------------------------------------------------------------------------
# Command: kosmo connect <url>
# ---------------------------------------------------------------------------

def cmd_connect(url_arg: Optional[str]) -> None:
    if not url_arg:
        current = get_server_url()
        print(f"Currently connected server: {c_cyan(current)}")
        print(f"Usage: kosmo connect <url-link-of-the-server>")
        return

    url = normalize_url(url_arg)
    print(f"Connecting to Kosmoporos server at: {c_bold(url)} ...")

    t0 = time.perf_counter()
    status_code, resp = http_get(f"{url}/api/v1/health", timeout=3.0)
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    cfg = load_config()
    cfg["server_url"] = url
    save_config(cfg)

    if status_code in (200, 204):
        print(f"{c_green('[SUCCESS]')} Connected to server at {c_cyan(url)} (HTTP {status_code}, Latency: {latency_ms} ms)")
    else:
        print(f"{c_yellow('[SAVED]')} Server address updated to {c_cyan(url)}")
        print(f"{c_yellow('[NOTE]')} Server appears offline or returned HTTP {status_code}. It will be used for future commands.")


# ---------------------------------------------------------------------------
# Command: kosmo send
# ---------------------------------------------------------------------------

def cmd_send(target: Optional[str] = None, send_all: bool = False, count: Optional[int] = None) -> None:
    server_url = get_server_url()
    cur_dir = Path.cwd()

    files_to_process: List[Path] = []
    target_path = Path(target) if target and target.lower() != "all" else None

    # Determine files to send
    if target_path and target_path.exists():
        if target_path.is_file():
            files_to_process = [target_path]
        elif target_path.is_dir():
            files_to_process = get_log_files_in_directory(target_path)
            if not files_to_process:
                print(f"{c_yellow('Notice:')} No valid log files found in directory: {target_path}")
                return
    elif send_all or (target and target.lower() == "all"):
        files_to_process = get_log_files_in_directory(cur_dir)
        if not files_to_process:
            print(f"{c_yellow('Notice:')} No valid log files found in current directory: {cur_dir}")
            return
    else:
        # Default: first log or file in current directory ordered as per date & time modified
        all_logs = get_log_files_in_directory(cur_dir)
        if all_logs:
            files_to_process = [all_logs[0]]
        elif target and not Path(target).exists():
            # The target might be a direct raw log string passed by user
            raw_log = target.strip()
            _send_raw_logs([raw_log], server_url, source="cli_direct", count_limit=count)
            return
        else:
            print(f"{c_yellow('Notice:')} No log files found in current directory: {cur_dir}")
            print(f"Hint: Place a .log or .txt file in this folder, or specify a path: kosmo send \"path/to/logfile.log\"")
            return

    # Extract log messages across selected file(s)
    log_messages: List[str] = []
    files_used: List[str] = []

    for fpath in files_to_process:
        remaining = (count - len(log_messages)) if count else None
        if count and remaining is not None and remaining <= 0:
            break
        lines = read_logs_from_file(fpath, max_count=remaining)
        if lines:
            log_messages.extend(lines)
            files_used.append(fpath.name)

    if not log_messages:
        print(f"{c_yellow('Notice:')} No log records found in selected file(s).")
        return

    _send_raw_logs(log_messages, server_url, files_used=files_used, count_limit=count)


def _send_raw_logs(logs: List[str], server_url: str, files_used: Optional[List[str]] = None, source: str = "kosmo_cli", count_limit: Optional[int] = None) -> None:
    if count_limit and len(logs) > count_limit:
        logs = logs[:count_limit]

    total_logs = len(logs)
    file_info = f"from {len(files_used)} file(s) ({', '.join(files_used[:3])}{'...' if len(files_used or []) > 3 else ''})" if files_used else "direct input"
    print(f"\n{c_bold('Kosmo Ingestion')} -> Target Server: {c_cyan(server_url)}")
    print(f"Sending {c_bold(str(total_logs))} log(s) {file_info} ...\n")

    t_start = time.perf_counter()
    success_count = 0
    failed_count = 0
    threats_detected = 0
    last_event_ids: List[str] = []

    # Send logs
    if total_logs > 20:
        # Batch transmission
        batch_size = 200
        for i in range(0, total_logs, batch_size):
            chunk = logs[i : i + batch_size]
            payload = {"logs": chunk, "source": source}
            code, resp = http_post(f"{server_url}/api/v1/ingest/batch", payload, timeout=15.0)
            if code in (200, 201):
                success_count += len(chunk)
                print(f" [{c_green('BATCH OK')}] Sent {i + len(chunk)}/{total_logs} logs -> HTTP {code}")
            else:
                failed_count += len(chunk)
                print(f" [{c_red('BATCH FAILED')}] Batch {i//batch_size + 1} failed: HTTP {code}")
    else:
        # Individual transmission with real-time feedback
        for idx, log_line in enumerate(logs, start=1):
            payload = {"log": log_line, "source": source}
            code, resp = http_post(f"{server_url}/api/v1/ingest", payload, timeout=6.0)
            if code in (200, 201):
                success_count += 1
                eid = resp.get("event_id", "OK") if isinstance(resp, dict) else "OK"
                fmt = resp.get("detected_format") or resp.get("format", "Detected") if isinstance(resp, dict) else "Detected"
                st = resp.get("status", "success") if isinstance(resp, dict) else "success"
                last_event_ids.append(eid)
                print(f" [{c_green('OK 200')}] Log #{idx:<3} | ID: {c_bold(eid):<16} | Format: {c_cyan(fmt):<12} | Status: {st}")
            else:
                failed_count += 1
                print(f" [{c_red('ERR ' + str(code))}] Log #{idx}: {resp}")

    t_elapsed = max(0.001, round(time.perf_counter() - t_start, 3))
    speed_eps = round(total_logs / t_elapsed, 1)

    # Check for threats among sent logs by querying recent events
    try:
        q_code, q_resp = http_get(f"{server_url}/api/v1/events?limit={min(100, total_logs)}")
        if q_code == 200 and isinstance(q_resp, dict):
            evs = q_resp.get("events", [])
            for ev in evs:
                sev = str(ev.get("severity", "")).lower()
                act = str(ev.get("action", "")).lower()
                if ev.get("threat") or sev in ("critical", "high") or act in ("block", "deny"):
                    threats_detected += 1
    except Exception:
        pass

    # Save session state for 'kosmo report'
    state_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server_url": server_url,
        "files_sent": files_used or ["direct_input"],
        "total_logs": total_logs,
        "success_count": success_count,
        "failed_count": failed_count,
        "threats_detected": threats_detected,
        "elapsed_seconds": t_elapsed,
        "speed_eps": speed_eps,
        "last_event_ids": last_event_ids[:5],
    }
    save_state(state_data)

    print("-" * 65)
    print(f"Result: {c_green(str(success_count))} sent successfully, {c_red(str(failed_count))} failed | Time: {t_elapsed}s ({c_bold(c_green(str(speed_eps) + ' logs/sec'))})")
    if threats_detected > 0:
        print(f"Alerts: {c_red(c_bold(str(threats_detected)))} threat events detected in recent traffic.")
    print("=" * 65 + "\n")


# ---------------------------------------------------------------------------
# Command: kosmo report & kosmo report save
# ---------------------------------------------------------------------------

def generate_report_table_string(server_url: str, session: Dict[str, Any], server_summary: Optional[Dict[str, Any]] = None) -> str:
    """Constructs a clean ASCII table view representation of the report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Metrics from session
    files_str = f"{len(session.get('files_sent', []))} file(s)"
    if session.get("files_sent"):
        files_str += f" ({', '.join(session['files_sent'][:2])}{'...' if len(session['files_sent']) > 2 else ''})"
    
    total_logs = session.get("total_logs", 0)
    success = session.get("success_count", 0)
    failed = session.get("failed_count", 0)
    threats = session.get("threats_detected", 0)
    speed = session.get("speed_eps", 0.0)
    elapsed = session.get("elapsed_seconds", 0.0)

    # Server-wide metrics
    srv_ing = server_summary.get("ingestion", {}) if server_summary else {}
    srv_sec = server_summary.get("security", {}) if server_summary else {}
    srv_ebpf = server_summary.get("ebpf_dpi_shield", {}) if server_summary else {}
    srv_tax = server_summary.get("taxonomy", {}) if server_summary else {}
    
    srv_processed = srv_ing.get("events_processed", total_logs)
    srv_rate = srv_ing.get("parse_success_rate", "100%")
    srv_eps = srv_ing.get("current_eps", 0.0)
    srv_sev = srv_sec.get("severity_distribution", {})

    # Precompute server threat and ebpf counts
    crit_cnt = srv_sev.get("critical", 0)
    high_cnt = srv_sev.get("high", 0)
    med_cnt = srv_sev.get("medium", 0)
    low_cnt = srv_sev.get("low", 0) + srv_sev.get("informational", 0)
    ebpf_pass = srv_ebpf.get("passed", 0)
    ebpf_drop = srv_ebpf.get("dropped", 0)

    width = 76
    sep_double = "+" + "=" * (width - 2) + "+"
    sep_single = "+" + "-" * 38 + "+" + "-" * 35 + "+"
    sep_section = "+" + "-" * (width - 2) + "+"

    lines = [
        sep_double,
        f"|{'KOSMOPOROS LOG PROCESSING & SECURITY AUDIT REPORT':^{width - 2}}|",
        f"|{f'Generated: {now_str} | Server: {server_url}':^{width - 2}}|",
        sep_double,
        f"| {'1. LOG TRANSMISSION & PARSING PERFORMANCE':<{width - 3}}|",
        sep_single,
        f"| {'Metric':<36} | {'Value':<33} |",
        sep_single,
        f"| {'Files Sent':<36} | {files_str:<33} |",
        f"| {'Total Logs Sent':<36} | {f'{total_logs} logs':<33} |",
        f"| {'Successfully Ingested Logs':<36} | {f'{success} logs':<33} |",
        f"| {'Failed / Dropped Logs':<36} | {f'{failed} logs':<33} |",
        f"| {'Parsing / Transmission Speed':<36} | {f'{speed} logs/sec':<33} |",
        f"| {'Total Ingestion Time':<36} | {f'{elapsed} seconds':<33} |",
        f"| {'Threat Logs Detected':<36} | {f'{threats} threat event(s)':<33} |",
        sep_section,
        f"| {'2. SERVER PIPELINE & SECURITY METRICS':<{width - 3}}|",
        sep_single,
        f"| {'Server Processed Events':<36} | {f'{srv_processed} total events':<33} |",
        f"| {'Server Parse Success Rate':<36} | {str(srv_rate):<33} |",
        f"| {'Server Real-Time EPS':<36} | {f'{srv_eps} logs/sec':<33} |",
        f"| {'Threat Severity (Critical)':<36} | {f'{crit_cnt} events':<33} |",
        f"| {'Threat Severity (High)':<36} | {f'{high_cnt} events':<33} |",
        f"| {'Threat Severity (Medium)':<36} | {f'{med_cnt} events':<33} |",
        f"| {'Threat Severity (Low/Info)':<36} | {f'{low_cnt} events':<33} |",
        f"| {'eBPF DPI Filter (Passed)':<36} | {f'{ebpf_pass} packets':<33} |",
        f"| {'eBPF Noise Dropped (Zero CPU)':<36} | {f'{ebpf_drop} noise packets':<33} |",
        sep_section,
        f"| {'3. DETECTED TAXONOMY & FORMAT DISTRIBUTION':<{width - 3}}|",
        sep_single,
    ]

    fmt_dist = srv_tax.get("format_distribution", {})
    if fmt_dist:
        for fmt, cnt in list(fmt_dist.items())[:5]:
            lines.append(f"| {fmt:<36} | {f'{cnt} events':<33} |")
    else:
        lines.append(f"| {'Default Deterministic Parsers':<36} | {'Active (CEF, Syslog, JSON, KV)':<33} |")

    lines.append(sep_double)
    return "\n".join(lines)


def cmd_report(save_flag: bool = False, save_dir: Optional[str] = None) -> None:
    server_url = get_server_url()
    session = load_state()

    # Query live server metrics
    server_summary = None
    code, resp = http_get(f"{server_url}/api/v1/reports/summary", timeout=4.0)
    if code == 200 and isinstance(resp, dict):
        server_summary = resp
    else:
        # Fallback to general metrics endpoint
        m_code, m_resp = http_get(f"{server_url}/api/v1/metrics", timeout=4.0)
        if m_code == 200 and isinstance(m_resp, dict):
            server_summary = {
                "ingestion": m_resp,
                "security": {},
                "taxonomy": {"format_distribution": m_resp.get("merkle_vault", {})},
                "ebpf_dpi_shield": {},
            }

    table_report = generate_report_table_string(server_url, session, server_summary)

    if save_flag or save_dir:
        # Target destination
        target_dir = Path(save_dir) if save_dir else Path.cwd()
        if not target_dir.exists():
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                print(f"{c_red('Error:')} Could not create directory '{target_dir}': {e}", file=sys.stderr)
                return

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_filename = f"kosmo_report_{timestamp_str}.txt"
        file_path = target_dir / report_filename

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(table_report + "\n")
            print(f"\n{c_green('[SAVED]')} Report successfully saved as table view text file:")
            print(f"         {c_bold(str(file_path.resolve()))}\n")
        except Exception as e:
            print(f"{c_red('Error:')} Failed to write report file: {e}", file=sys.stderr)
    else:
        # Print table report to terminal
        print("\n" + table_report + "\n")


# ---------------------------------------------------------------------------
# Command: kosmo --help
# ---------------------------------------------------------------------------

def cmd_help() -> None:
    help_text = f"""
{c_bold('Kosmo CLI')} — Universal Log Processing Framework Terminal Tool

{c_bold('Usage:')}
  kosmo <command> [arguments] [options]

{c_bold('Commands:')}
  {c_cyan('kosmo connect <url-link-of-the-server>')}
    Connect to a specific server URL (e.g. http://127.0.0.1:8000).
    If not specified, http://localhost:8000 is used by default.

  {c_cyan('kosmo send')}
    Send the first log or file in the current directory to the server
    (ordered by date and time modified).

  {c_cyan('kosmo send all')}
    Send all logs or files in the current directory to the server.

  {c_cyan('kosmo send "directory or file path"')}
    Send a specific log file or all files in a specified directory.

  {c_cyan('kosmo send -n <number>')}
    Send a specific number of logs from the current directory.

  {c_cyan('kosmo send "directory_path" -n <number>')}
    Send a specific number of logs from a specified directory or file.

  {c_cyan('kosmo report')}
    Display terminal report of files sent, parsing speeds, successfully sent logs,
    failed logs, and threat logs detected.

  {c_cyan('kosmo report save')}
    Save the report in the current directory as a formatted table-view .txt file.

  {c_cyan('kosmo report save "directory_path"')}
    Save the report as a formatted table-view .txt file to a specified directory location.

  {c_cyan('kosmo --help')}
    Display this help menu with descriptions for all available commands.
"""
    print(help_text)


# ---------------------------------------------------------------------------
# Main Argument Dispatcher
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h", "help"):
        cmd_help()
        return

    command = args[0].lower()

    # 1. kosmo connect <url>
    if command == "connect":
        url_arg = args[1] if len(args) > 1 else None
        cmd_connect(url_arg)

    # 2. kosmo send [...]
    elif command == "send":
        target = None
        send_all = False
        count = None

        idx = 1
        while idx < len(args):
            arg = args[idx]
            if arg in ("-n", "--count") and idx + 1 < len(args):
                try:
                    count = int(args[idx + 1])
                except ValueError:
                    print(f"{c_red('Error:')} -n requires an integer count.", file=sys.stderr)
                    sys.exit(1)
                idx += 2
                continue
            elif arg.lower() == "all":
                send_all = True
            elif not arg.startswith("-") and not target:
                target = arg
            idx += 1

        cmd_send(target=target, send_all=send_all, count=count)

    # 3. kosmo report [...]
    elif command == "report":
        save_flag = False
        save_dir = None

        if len(args) > 1:
            sub = args[1].lower()
            if sub == "save":
                save_flag = True
                if len(args) > 2:
                    save_dir = args[2]

        cmd_report(save_flag=save_flag, save_dir=save_dir)

    else:
        print(f"{c_red('Unknown command:')} 'kosmo {command}'", file=sys.stderr)
        print("Run 'kosmo --help' to see all valid commands.")
        sys.exit(1)


if __name__ == "__main__":
    main()
