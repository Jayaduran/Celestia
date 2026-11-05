import json
import socket
import threading
from typing import Dict, Any
from kosmoporos.ai.ai_engine import KosmoporosAiEngine

class AiSidecar:
    """
    Sovereign AI Threat Intelligence Sidecar.
    Runs asynchronously and out-of-band to prevent blocking the C-Core parser.
    Listens on TCP 3002 for unparsed/unknown logs, scores them, and forwards the insights directly to Node.js IPC.
    """
    def __init__(self, bind_port=3002, node_ipc_port=3001):
        self.bind_port = bind_port
        self.node_ipc_port = node_ipc_port
        self.ai_engine = KosmoporosAiEngine()
        self.running = False
        self._server_socket = None

    def _connect_node_ipc(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', self.node_ipc_port))
            return s
        except Exception as e:
            print(f"[AI Sidecar] Cannot connect to Node IPC: {e}")
            return None

    def _process_log(self, data: str):
        try:
            payload = json.loads(data)
            raw_msg = payload.get("raw_message", "")
            event_id = payload.get("event_id", "UNKNOWN_EID")
            source = payload.get("source", "unknown")

            # Blocking LLM or heuristic call (runs in isolated thread pool / sidecar process)
            print(f"[AI Sidecar] Analyzing unknown log: {event_id}")
            ai_data = self.ai_engine.parse_unknown_log(raw_msg)
            
            if not ai_data:
                return
            
            # Format as an AI Insight event for the UI
            insight_event = {
                "type": "AI_INSIGHT",
                "data": {
                    "event_id": event_id,
                    "source": source,
                    "format": "AI-Inferred",
                    "status": "success",
                    "parser_used": "ai_engine",
                    "raw_message": raw_msg,
                    "threat": {
                        "threat_type": ai_data.get("threat_type", "Anomaly"),
                        "severity": ai_data.get("severity", "medium"),
                        "detail": ai_data.get("summary", "Structure inferred via Sovereign AI")
                    },
                    "extracted_fields": ai_data.get("extracted_fields", {}),
                    "ai_inferred_fields": {
                        "source_ip": ai_data.get("source_ip"),
                        "destination_ip": ai_data.get("destination_ip"),
                        "action": ai_data.get("event_action"),
                        "protocol": ai_data.get("protocol")
                    }
                }
            }

            # Forward to Node.js Gateway
            node_sock = self._connect_node_ipc()
            if node_sock:
                node_sock.sendall((json.dumps(insight_event) + '\n').encode('utf-8'))
                node_sock.close()
                print(f"[AI Sidecar] Forwarded AI Insight to UI for {event_id}")
                
        except Exception as e:
            print(f"[AI Sidecar] Error processing log: {e}")

    def _handle_client(self, conn: socket.socket):
        with conn:
            buffer = ""
            while self.running:
                data = conn.recv(8192)
                if not data:
                    break
                buffer += data.decode('utf-8')
                lines = buffer.split('\n')
                buffer = lines.pop()
                for line in lines:
                    if line.strip():
                        # Process in background thread to avoid blocking the receiver
                        threading.Thread(target=self._process_log, args=(line,), daemon=True).start()

    def start(self):
        self.running = True
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind(('127.0.0.1', self.bind_port))
        self._server_socket.listen(100)
        print(f"[AI Sidecar] Listening for unknown logs on 127.0.0.1:{self.bind_port}")

        try:
            while self.running:
                conn, addr = self._server_socket.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
        except Exception as e:
            if self.running:
                print(f"[AI Sidecar] Server error: {e}")

    def stop(self):
        self.running = False
        if self._server_socket:
            self._server_socket.close()
            print("[AI Sidecar] Stopped.")

if __name__ == "__main__":
    sidecar = AiSidecar()
    try:
        sidecar.start()
    except KeyboardInterrupt:
        sidecar.stop()
