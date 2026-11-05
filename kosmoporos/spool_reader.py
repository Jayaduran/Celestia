import os
import time
import json
import threading
import socket
from pathlib import Path
from typing import Optional, Callable, Dict, Any
from kosmoporos.engine import KosmoporosEngine

class SpoolReader:
    """
    Direct-on-Storage Spool Reader.
    Tails the zero-copy spool file written by the JS Ingress Gateway.
    Feeds raw logs into the Kosmoporos Engine for parsing, threat detection, and Merkle Vault sealing.
    Communicates via IPC TCP with the Node.js Control Plane.
    """
    def __init__(self, spool_file: str, engine: Optional[KosmoporosEngine] = None, on_parsed: Optional[Callable] = None):
        self.spool_file = Path(spool_file)
        self.engine = engine or KosmoporosEngine()
        self.running = False
        self.on_parsed = on_parsed
        self._thread = None
        self._ipc_socket = None
        self._ai_socket = None
        self._connect_ipc()
        self._connect_ai_sidecar()

    def _connect_ipc(self):
        try:
            self._ipc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._ipc_socket.connect(('127.0.0.1', 3001))
            print("[SpoolReader] Connected to Node.js IPC Server")
        except Exception as e:
            print(f"[SpoolReader] Failed to connect to Node IPC Server: {e}. Will retry on write.")
            self._ipc_socket = None

    def _connect_ai_sidecar(self):
        try:
            self._ai_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._ai_socket.connect(('127.0.0.1', 3002))
            print("[SpoolReader] Connected to AI Sidecar")
        except Exception as e:
            print(f"[SpoolReader] Failed to connect to AI Sidecar: {e}. Will retry on write.")
            self._ai_socket = None

    def _send_ipc(self, message: Dict[str, Any]):
        if not self._ipc_socket:
            self._connect_ipc()
        if self._ipc_socket:
            try:
                self._ipc_socket.sendall((json.dumps(message) + '\n').encode('utf-8'))
            except Exception:
                self._ipc_socket = None

    def _send_to_ai_sidecar(self, message: Dict[str, Any]):
        if not self._ai_socket:
            self._connect_ai_sidecar()
        if self._ai_socket:
            try:
                self._ai_socket.sendall((json.dumps(message) + '\n').encode('utf-8'))
            except Exception:
                self._ai_socket = None

    def _stats_loop(self):
        while self.running:
            time.sleep(5) # Send stats every 5 seconds
            try:
                stats = self.engine.get_statistics()
                self._send_ipc({
                    "type": "STATS_UPDATE",
                    "data": stats
                })
            except Exception as e:
                print(f"[SpoolReader] Error pushing stats: {e}")

    def _tail_spool(self):
        # Wait for file to exist
        while not self.spool_file.exists() and self.running:
            time.sleep(0.1)

        if not self.running:
            return

        # Start stats loop thread
        threading.Thread(target=self._stats_loop, daemon=True).start()

        with open(self.spool_file, 'r', encoding='utf-8') as f:
            # For real-time, optionally seek to end if we don't want to replay old logs
            # f.seek(0, os.SEEK_END)
            
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.01) # 10ms wait for new data
                    continue
                
                parts = line.strip().split('|', 2)
                if len(parts) == 3:
                    ts_str, source, payload = parts
                    try:
                        result = self.engine.parse_stored_log(
                            raw_payload=payload,
                            source=source
                        )
                        
                        # Forward parsed event to Node.js WebSocket layer via IPC
                        event_data = {
                            "event_id": result.event_id,
                            "source": source,
                            "format": result.format,
                            "status": result.status,
                            "parser_used": result.parser_used,
                            "raw_message": result.raw_message,
                            "threat": result.threat.to_dict() if getattr(result, "threat", None) else None,
                            "merkle_root": result.merkle_root,
                            "merkle_block_id": result.merkle_block_id
                        }
                        
                        if result.status == "unparsed":
                            # Send to AI Sidecar (Out-of-band Processing)
                            self._send_to_ai_sidecar({
                                "event_id": result.event_id,
                                "source": source,
                                "raw_message": result.raw_message
                            })
                            # We still forward the initial event so the UI knows it's pending review
                            event_data["status"] = "pending_ai_review"
                            
                        self._send_ipc({
                            "type": "NEW_EVENT",
                            "data": event_data
                        })

                        if self.on_parsed:
                            self.on_parsed(result)
                            
                    except Exception as e:
                        print(f"[SpoolReader] Error parsing log: {e}")

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._tail_spool, daemon=True)
        self._thread.start()
        print(f"[Kosmoporos] Spool Reader started. Tailing {self.spool_file}")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=1.0)
            print("[Kosmoporos] Spool Reader stopped.")

