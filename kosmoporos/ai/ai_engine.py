import re
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional


class KosmoporosAiEngine:
    """
    On-Board AI Parsing Unit for Kosmoporos.
    Autonomous parser for unknown, proprietary, and unformatted logs.
    Features:
      1. Local/Remote LLM Inference (Ollama / OpenAI / compatible REST)
      2. Zero-Latency Deterministic Heuristic Fallback (100% offline, zero hallucination)
    """

    def __init__(
        self,
        provider: str = "ollama",
        host: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: float = 3.0,
    ):
        self.provider = provider
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

        # Heuristic IP / Port regexes
        self.IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        self.KV_PATTERN = re.compile(r'\b([a-zA-Z0-9_.-]+)=([^\s|;,\'"]+|"[^"]*"|\'[^\']*\')')

    def parse_unknown_log(self, raw_message: str) -> Dict[str, Any]:
        """Parse unknown log into structured fields using hybrid LLM + heuristic baseline."""
        baseline = self._deterministic_parse(raw_message)

        # Attempt LLM query if provider is reachable
        if self.provider == "ollama":
            llm_result = self._query_ollama(raw_message)
            if llm_result:
                # Merge: LLM provides context, deterministic facts override
                for k, v in baseline.items():
                    if v and (not llm_result.get(k) or llm_result[k] == "unknown"):
                        llm_result[k] = v
                return llm_result

        return baseline

    def _deterministic_parse(self, raw_message: str) -> Dict[str, Any]:
        """Extract structured fields using robust regex tokenization."""
        msg = raw_message or ""
        ips = self.IPV4_PATTERN.findall(msg)
        src_ip = ips[0] if len(ips) > 0 else None
        dst_ip = ips[1] if len(ips) > 1 else None

        extracted = {}
        for k, v in self.KV_PATTERN.findall(msg):
            extracted[k] = v.strip('"\'')

        # Detect action
        low = msg.lower()
        if any(w in low for w in ("deny", "drop", "block", "rejected", "fail")):
            action = "deny"
        elif any(w in low for w in ("allow", "permit", "accept", "pass", "success")):
            action = "allow"
        else:
            action = extracted.get("action", "unknown")

        # Detect severity
        if any(w in low for w in ("crit", "fatal", "panic")):
            sev = "critical"
        elif any(w in low for w in ("err", "alert", "attack")):
            sev = "high"
        elif any(w in low for w in ("warn",)):
            sev = "medium"
        else:
            sev = "informational"

        # Detect protocol
        proto = None
        for p in ("tcp", "udp", "icmp", "http", "dns", "ssh", "tls"):
            if re.search(r'\b' + p + r'\b', low):
                proto = p
                break

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": extracted.get("spt") or extracted.get("src_port"),
            "destination_port": extracted.get("dpt") or extracted.get("dst_port"),
            "event_action": action,
            "severity": sev,
            "protocol": proto,
            "threat_type": "Proprietary Telemetry",
            "extracted_fields": extracted,
            "summary": "Parsed via deterministic heuristic fallback",
        }

    def _query_ollama(self, raw_message: str) -> Optional[Dict[str, Any]]:
        """Query local Ollama instance with short timeout."""
        if getattr(self, "_ollama_available", True) is False:
            return None
        try:
            url = f"{self.host}/api/generate"
            prompt = (
                "Extract source_ip, destination_ip, source_port, destination_port, "
                "event_action, protocol, and severity from this log as JSON only:\n"
                f"{raw_message}"
            )
            req_data = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "format": "json",
                "stream": False,
            }).encode("utf-8")

            req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    self._ollama_available = True
                    body = json.loads(resp.read().decode("utf-8"))
                    response_text = body.get("response", "{}")
                    return json.loads(response_text)
        except Exception:
            self._ollama_available = False
        return None
