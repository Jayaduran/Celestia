import re
from typing import Dict, Any, Optional, Set
from kosmoporos.models import ThreatVerdict


class ThreatDetector:
    """
    Self-contained Threat Detector for Kosmoporos.
    Evaluates raw payload exploit patterns, IP blacklists, and canonical events.
    """

    def __init__(self, blocked_ips: Optional[Set[str]] = None, ai_scorer: Optional[Any] = None):
        self.blocked_ips = blocked_ips or set()
        self.ai_scorer = ai_scorer

        # Precompiled exploit signatures: (Pattern, Threat Type, Description, Score)
        self.rules = [
            # High-Profile Exploits
            (re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop|http)", re.I), "Log4Shell (JNDI)", "JNDI lookup injection", 10),
            (re.compile(r"169\.254\.169\.254"), "SSRF", "Cloud metadata endpoint access attempt", 8),

            # SQL Injection
            (re.compile(r"('|\b)(or|and)\b\s+['\"\d]+=['\"\d]+", re.I), "SQL Injection", "Boolean OR/AND injection", 8),
            (re.compile(r"union\s+(all\s+)?select", re.I), "SQL Injection", "UNION SELECT query", 9),
            (re.compile(r"drop\s+table", re.I), "SQL Injection", "Destructive DROP TABLE command", 10),
            (re.compile(r"information_schema", re.I), "SQL Injection", "Database metadata enumeration", 6),
            (re.compile(r"--\s*$", re.M), "SQL Injection", "Inline SQL comment truncation", 5),
            (re.compile(r"/\*.*?\*/"), "SQL Injection", "Block comment syntax", 5),
            (re.compile(r"admin'--", re.I), "SQL Injection", "Classic auth bypass attempt", 7),
            (re.compile(r"\b1=1\b"), "SQL Injection", "Tautology condition injection", 5),

            # Cross-Site Scripting (XSS)
            (re.compile(r"<script.*?>", re.I), "XSS", "Injected <script> HTML tag", 7),
            (re.compile(r"javascript:", re.I), "XSS", "Inline javascript pseudo-protocol", 6),
            (re.compile(r"onerror\s*=", re.I), "XSS", "DOM Event handler hijacking (onerror)", 6),
            (re.compile(r"onload\s*=", re.I), "XSS", "DOM Event handler hijacking (onload)", 6),
            (re.compile(r"<img\s+[^>]*?src=x", re.I), "XSS", "Malicious image tag injection", 5),
            (re.compile(r"alert\(", re.I), "XSS", "Interactive JavaScript execution test", 5),

            # Path Traversal & LFI
            (re.compile(r"\.\./\.\./"), "Path Traversal / LFI", "Directory backtracking (../)", 8),
            (re.compile(r"\.\.\\\.\.\\"), "Path Traversal / LFI", "Windows directory backtracking (..\\)", 8),
            (re.compile(r"/etc/passwd"), "Path Traversal / LFI", "Sensitive credential file target", 9),
            (re.compile(r"win\.ini", re.I), "Path Traversal / LFI", "Windows configuration file target", 8),

            # Command Injection / RCE
            (re.compile(r";\s*rm\s+-rf", re.I), "Command Injection", "Destructive rm -rf command", 10),
            (re.compile(r";\s*cat\s+/etc", re.I), "Command Injection", "Arbitrary file read attempt", 9),
            (re.compile(r"\|\s*bash", re.I), "Command Injection", "Pipe to bash subshell", 9),
            (re.compile(r"powershell\s+-enc", re.I), "Command Injection", "Obfuscated PowerShell execution", 8),

            # Automated Scanners
            (re.compile(r"nikto/", re.I), "Automated Scanner", "Nikto web vulnerability scanner", 4),
            (re.compile(r"sqlmap/", re.I), "Automated Scanner", "sqlmap automated SQLi tool", 6),
            (re.compile(r"nmap\s+scripting\s+engine", re.I), "Automated Scanner", "Nmap NSE script detection", 4),
        ]

    def evaluate(
        self,
        raw_message: str,
        src_ip: Optional[str] = None,
        canonical_event: Optional[Any] = None,
    ) -> ThreatVerdict:
        """Evaluate log string and canonical event for security attack vectors."""
        msg = raw_message or ""
        ip = src_ip or ""
        if not ip and canonical_event and hasattr(canonical_event, "source") and canonical_event.source:
            ip = getattr(canonical_event.source, "ip", "") or ""

        # 1. Critical IP Blacklist Check
        if ip and ip in self.blocked_ips:
            return ThreatVerdict(
                is_threat=True,
                threat_type="Blocked IP Violation",
                severity="critical",
                detail=f"Traffic detected from blacklisted IP address {ip}",
                signature=f"Blacklist match: {ip}",
                score=10,
            )

        total_score = 0
        triggered_signatures = []
        threat_types = set()

        # 2. Pattern Signatures Check
        for pattern, t_type, desc, score in self.rules:
            if pattern.search(msg):
                total_score += score
                threat_types.add(t_type)
                triggered_signatures.append(f"[{t_type}] {desc} ({score} pts)")

        # 3. Optional AI Scorer Check
        if self.ai_scorer and callable(self.ai_scorer):
            try:
                ai_res = self.ai_scorer(raw_message)
                if ai_res and ai_res.get("is_anomalous"):
                    total_score += 5
                    ai_type = ai_res.get("threat_type") or "AI Anomaly"
                    threat_types.add(ai_type)
                    triggered_signatures.append(f"[AI Model] Anomaly Detected ({ai_type})")
            except Exception:
                pass

        if total_score == 0:
            return ThreatVerdict(is_threat=False, severity="informational")

        if total_score >= 10:
            sev = "critical"
        elif total_score >= 7:
            sev = "high"
        elif total_score >= 4:
            sev = "medium"
        else:
            sev = "low"

        summary_type = list(threat_types)[0] if len(threat_types) == 1 else "Multi-Vector Attack"

        return ThreatVerdict(
            is_threat=True,
            threat_type=summary_type,
            severity=sev,
            detail=f"Heuristic Score: {total_score}. Detected {len(triggered_signatures)} threat signatures.",
            signature=" | ".join(triggered_signatures),
            score=total_score,
        )
