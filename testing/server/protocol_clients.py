"""
ULPF Network Protocol Simulator Clients.
Implements real network socket connections (UDP, TCP, HTTP REST, File Drop)
to transmit custom and simulated security logs to the ULPF Main Worker.
"""

import socket
import time
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional, Tuple


def probe_socket(host: str, port: int, protocol: str = "tcp", timeout: float = 2.0) -> Dict[str, Any]:
    """Test connection availability and latency to target host and port."""
    start_time = time.perf_counter()
    protocol = protocol.lower()

    if protocol == "udp":
        # UDP is connectionless; test socket creation and basic datagram probe
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # Send small null probe datagram
            sock.sendto(b"", (host, port))
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            sock.close()
            return {
                "status": "ready",
                "protocol": "udp",
                "host": host,
                "port": port,
                "latency_ms": latency_ms,
                "detail": f"UDP socket opened to {host}:{port}",
            }
        except Exception as e:
            return {
                "status": "error",
                "protocol": "udp",
                "host": host,
                "port": port,
                "error": str(e),
            }

    elif protocol in ("tcp", "tls"):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            sock.close()
            return {
                "status": "connected",
                "protocol": "tcp",
                "host": host,
                "port": port,
                "latency_ms": latency_ms,
                "detail": f"TCP connection handshake succeeded on {host}:{port}",
            }
        except Exception as e:
            return {
                "status": "disconnected",
                "protocol": "tcp",
                "host": host,
                "port": port,
                "error": str(e),
                "detail": f"Could not connect to TCP {host}:{port}",
            }

    elif protocol in ("http", "https"):
        scheme = "https" if protocol == "https" else "http"
        # Test raw TCP socket with WAN-tolerant timeout (min 1.5s, max 3.5s)
        tcp_timeout = max(1.5, min(timeout, 3.5))
        try:
            with socket.create_connection((host, port), timeout=tcp_timeout):
                pass
        except OSError as e:
            return {
                "status": "offline",
                "protocol": "http",
                "host": host,
                "port": port,
                "error": str(e),
                "detail": f"Port {port} on {host} is closed or unreachable ({type(e).__name__})",
            }

        # Candidate paths for server health / status / root
        candidate_paths = ["/api/v1/health/live", "/api/v1/health", "/health", "/api/v1/status", "/dashboard/index.html", "/"]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        last_error = None
        http_timeout = max(2.0, min(timeout, 4.0))

        for path in candidate_paths:
            url = f"{scheme}://{host}:{port}{path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ULPF-Testing-Client/1.0"})
                with opener.open(req, timeout=http_timeout) as response:
                    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    status_str = "online" if response.status in (200, 204, 301, 302, 307, 308) else "degraded"
                    return {
                        "status": status_str,
                        "protocol": "http",
                        "host": host,
                        "port": port,
                        "status_code": response.status,
                        "latency_ms": latency_ms,
                        "detail": f"HTTP GET {url} returned HTTP {response.status}",
                    }
            except urllib.error.HTTPError as e:
                # If HTTP server responded with any HTTP status code (2xx, 3xx, 4xx), the server IS ONLINE!
                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return {
                    "status": "online" if e.code < 400 else "ready",
                    "protocol": "http",
                    "host": host,
                    "port": port,
                    "status_code": e.code,
                    "latency_ms": latency_ms,
                    "detail": f"HTTP service responding on {host}:{port} ({path} returned HTTP {e.code})",
                }
            except Exception as e:
                last_error = e
                continue

        # If candidate GETs timed out or failed, but TCP port was open, report socket is listening
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "ready",
            "protocol": "http",
            "host": host,
            "port": port,
            "latency_ms": latency_ms,
            "detail": f"Port {port} on {host} is OPEN and accepting connections (HTTP endpoint probe: {str(last_error)})",
        }

    return {"status": "unsupported_protocol", "protocol": protocol}


def send_udp_log(host: str, port: int, payload: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Transmits a log message as a UDP Syslog datagram with configurable timeout."""
    start_time = time.perf_counter()
    data = payload.strip().encode("utf-8")
    bytes_sent = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        bytes_sent = sock.sendto(data, (host, port))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        return {
            "success": True,
            "protocol": "UDP",
            "destination": f"{host}:{port}",
            "bytes_sent": bytes_sent,
            "latency_ms": latency_ms,
            "timeout": timeout,
            "payload_preview": payload[:120] + ("..." if len(payload) > 120 else ""),
            "detail": f"Transmitted {bytes_sent} bytes via UDP datagram to {host}:{port} (timeout: {timeout}s)",
        }
    except (socket.timeout, TimeoutError):
        return {
            "success": False,
            "protocol": "UDP",
            "destination": f"{host}:{port}",
            "error": f"UDP device socket timed out after {timeout}s",
            "timeout": True,
            "bytes_sent": 0,
        }
    except Exception as e:
        return {
            "success": False,
            "protocol": "UDP",
            "destination": f"{host}:{port}",
            "error": str(e),
            "bytes_sent": 0,
        }


def send_tcp_log(host: str, port: int, payload: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Transmits a log message over a streaming TCP socket connection with configurable timeout."""
    start_time = time.perf_counter()
    # RFC 5424 / octet framing or newline-delimited message
    msg = payload.strip() + "\n"
    data = msg.encode("utf-8")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(data)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        sock.close()
        return {
            "success": True,
            "protocol": "TCP",
            "destination": f"{host}:{port}",
            "bytes_sent": len(data),
            "latency_ms": latency_ms,
            "timeout": timeout,
            "payload_preview": payload[:120] + ("..." if len(payload) > 120 else ""),
            "detail": f"Streamed {len(data)} bytes over TCP socket to {host}:{port} (timeout: {timeout}s)",
        }
    except (socket.timeout, TimeoutError):
        return {
            "success": False,
            "protocol": "TCP",
            "destination": f"{host}:{port}",
            "error": f"TCP connection timed out after {timeout}s",
            "timeout": True,
            "bytes_sent": 0,
        }
    except Exception as e:
        return {
            "success": False,
            "protocol": "TCP",
            "destination": f"{host}:{port}",
            "error": str(e),
            "bytes_sent": 0,
        }


def send_http_log(api_url: str, payload: str, source: str = "Test-Client", vendor: Optional[str] = None, timeout: float = 10.0) -> Dict[str, Any]:
    """Transmits a log payload via HTTP POST /api/v1/ingest with configurable timeout."""
    start_time = time.perf_counter()
    body = {
        "message": payload.strip(),
        "source": source,
    }
    if vendor:
        body["vendor"] = vendor

    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ULPF-Testing-Simulator/1.0",
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8")
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            parsed_resp = json.loads(resp_body) if resp_body.startswith("{") else {"raw": resp_body}
            return {
                "success": True,
                "protocol": "HTTP",
                "destination": api_url,
                "status_code": resp.status,
                "bytes_sent": len(data),
                "latency_ms": latency_ms,
                "timeout": timeout,
                "response": parsed_resp,
                "payload_preview": payload[:120] + ("..." if len(payload) > 120 else ""),
                "detail": f"HTTP POST returned {resp.status} in {latency_ms}ms",
            }
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        return {
            "success": False,
            "protocol": "HTTP",
            "destination": api_url,
            "status_code": e.code,
            "error": f"HTTP {e.code}: {err_body}",
            "bytes_sent": len(data),
        }
    except (TimeoutError, urllib.error.URLError) as e:
        if isinstance(e, TimeoutError) or "timed out" in str(e).lower():
            return {
                "success": False,
                "protocol": "HTTP",
                "destination": api_url,
                "error": f"HTTP request timed out after {timeout}s",
                "timeout": True,
                "bytes_sent": len(data),
            }
        return {
            "success": False,
            "protocol": "HTTP",
            "destination": api_url,
            "error": str(e),
            "bytes_sent": len(data),
        }
    except Exception as e:
        return {
            "success": False,
            "protocol": "HTTP",
            "destination": api_url,
            "error": str(e),
            "bytes_sent": len(data),
        }


def drop_file_log(watch_dir: str, payload: str, filename: Optional[str] = None) -> Dict[str, Any]:
    """Simulates file-based collector by writing directly to watched log directory."""
    start_time = time.perf_counter()
    target_dir = Path(watch_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    fname = filename or f"simulated_ingest_{int(time.time())}.log"
    target_file = target_dir / fname

    try:
        with open(target_file, "a", encoding="utf-8") as f:
            f.write(payload.strip() + "\n")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        bytes_written = len(payload.encode("utf-8"))
        return {
            "success": True,
            "protocol": "FILE",
            "destination": str(target_file),
            "bytes_sent": bytes_written,
            "latency_ms": latency_ms,
            "payload_preview": payload[:120] + ("..." if len(payload) > 120 else ""),
            "detail": f"Appended {bytes_written} bytes to {target_file}",
        }
    except Exception as e:
        return {
            "success": False,
            "protocol": "FILE",
            "destination": str(target_file),
            "error": str(e),
            "bytes_sent": 0,
        }
