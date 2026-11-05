import asyncio
import logging
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timezone
from app.collectors.base import BaseConnector
from app.collectors.ingress import RawIngress
from app.collectors.queue import IngestionQueue
from app.config import settings

logger = logging.getLogger(__name__)


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector):
        self.collector = collector
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        self.collector.handle_datagram(data, addr)


class SyslogUDPCollector(BaseConnector):
    """
    RFC 3164 / RFC 5424 UDP Syslog Ingress Collector (AsyncIO).
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        queue: Optional[IngestionQueue] = None,
        event_callback: Optional[Callable] = None,
    ):
        super().__init__(name="Syslog UDP Collector", connector_type="syslog_udp")
        self.host = host or settings.syslog_udp_host
        self.port = port or settings.syslog_udp_port
        self.queue = queue
        self.event_callback = event_callback
        self.transports = []

    async def start_async(self) -> None:
        """Start UDP listener across configured port + port 514."""
        if self.is_running:
            return

        self.transports = []
        ports_to_try = [self.port]
        if 514 not in ports_to_try:
            ports_to_try.append(514)

        loop = asyncio.get_running_loop()

        for p in ports_to_try:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: SyslogUDPProtocol(self),
                    local_addr=(self.host, p)
                )
                self.transports.append(transport)
                logger.info(f"Async Syslog UDP Collector listening on {self.host}:{p}")
            except Exception as e:
                logger.warning(f"Could not bind Syslog UDP server on {self.host}:{p}: {e}")

        if not self.transports:
            logger.error(f"Failed to bind any Syslog UDP port on {self.host}")
            self.is_running = False
            return

        self.is_running = True
        self.started_at = datetime.now(timezone.utc).isoformat()

    def handle_datagram(self, data: bytes, addr: tuple) -> None:
        if not self.is_running:
            return
            
        self.total_received += 1
        self.bytes_received += len(data)

        raw_log = data.decode("utf-8", errors="replace").strip()
        if not raw_log:
            return

        client_ip, client_port = addr[0], addr[1]
        source_identifier = client_ip

        ingress = RawIngress(
            connector_type="syslog_udp",
            source=source_identifier,
            raw_text=raw_log,
            transport_metadata={
                "protocol": "UDP",
                "client_ip": client_ip,
                "client_port": client_port,
                "bytes": len(data),
            }
        )

        if self.queue:
            accepted, reason = self.queue.enqueue(ingress)
            if accepted:
                self.total_accepted += 1
                self.total_processed += 1
            else:
                self.total_rejected += 1
                if "RATE_LIMIT" in reason:
                    self.total_dropped_rate_limit += 1
        elif self.event_callback:
            self.total_accepted += 1
            self.total_processed += 1
            self.event_callback(ingress)

    def stop(self) -> None:
        self.is_running = False
        for transport in self.transports:
            try:
                transport.close()
            except Exception:
                pass
        self.transports.clear()
        if hasattr(self, "_thread_loop") and self._thread_loop and self._thread_loop.is_running():
            try:
                self._thread_loop.call_soon_threadsafe(self._thread_loop.stop)
            except Exception:
                pass
        logger.info("Async Syslog UDP Collector stopped.")

    def start(self):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.start_async())
        except RuntimeError:
            import threading
            self._thread_loop = asyncio.new_event_loop()
            def _run():
                asyncio.set_event_loop(self._thread_loop)
                self._thread_loop.run_until_complete(self.start_async())
                self._thread_loop.run_forever()
            self._bg_thread = threading.Thread(target=_run, daemon=True)
            self._bg_thread.start()
            import time
            time.sleep(0.05)


class SyslogTCPCollector(BaseConnector):
    """
    RFC 3164 / RFC 5424 TCP Syslog Ingress Collector (AsyncIO).
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        queue: Optional[IngestionQueue] = None,
        event_callback: Optional[Callable] = None,
    ):
        super().__init__(name="Syslog TCP Collector", connector_type="syslog_tcp")
        self.host = host or settings.syslog_tcp_host
        self.port = port or settings.syslog_tcp_port
        self.queue = queue
        self.event_callback = event_callback
        self.server = None
        self._client_tasks = set()

    async def start_async(self) -> None:
        if self.is_running:
            return

        try:
            self.server = await asyncio.start_server(
                self.handle_client, self.host, self.port
            )
            self.is_running = True
            self.started_at = datetime.now(timezone.utc).isoformat()
            logger.info(f"Async Syslog TCP Collector listening on {self.host}:{self.port}")
        except Exception as e:
            logger.warning(f"Could not bind Syslog TCP server on {self.host}:{self.port}: {e}")
            self.is_running = False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info('peername')
        if not addr:
            return
            
        client_ip, client_port = addr[0], addr[1]
        buffer = ""
        current_task = None
        try:
            current_task = asyncio.current_task()
            if current_task:
                self._client_tasks.add(current_task)
        except Exception:
            pass

        try:
            while self.is_running:
                data = await reader.read(4096)
                if not data:
                    break

                self.bytes_received += len(data)
                text = data.decode("utf-8", errors="replace")
                buffer += text

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    raw_log = line.strip()
                    if not raw_log:
                        continue

                    self.total_received += 1
                    ingress = RawIngress(
                        connector_type="syslog_tcp",
                        source=client_ip,
                        raw_text=raw_log,
                        transport_metadata={
                            "protocol": "TCP",
                            "client_ip": client_ip,
                            "client_port": client_port,
                            "server_port": self.port,
                        }
                    )

                    if self.queue:
                        accepted, reason = self.queue.enqueue(ingress)
                        while not accepted and self.is_running:
                            self.total_rejected += 1
                            if "RATE_LIMIT" in reason:
                                self.total_dropped_rate_limit += 1
                            # Priority 14: Stall TCP connections via asyncio backpressure
                            await asyncio.sleep(0.1)
                            accepted, reason = self.queue.enqueue(ingress)
                            
                        if accepted:
                            self.total_accepted += 1
                            self.total_processed += 1
                    elif self.event_callback:
                        self.total_accepted += 1
                        self.total_processed += 1
                        self.event_callback(ingress)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            if self.is_running:
                self.total_errors += 1
                logger.error(f"[AsyncSyslogTCP] Client handler error ({client_ip}): {e}")
        finally:
            if current_task:
                self._client_tasks.discard(current_task)
            try:
                writer.close()
            except Exception:
                pass

    def stop(self) -> None:
        self.is_running = False
        for task in list(self._client_tasks):
            try:
                task.cancel()
            except Exception:
                pass
        self._client_tasks.clear()
        if self.server:
            try:
                self.server.close()
            except Exception:
                pass
        if hasattr(self, "_thread_loop") and self._thread_loop and self._thread_loop.is_running():
            try:
                self._thread_loop.call_soon_threadsafe(self._thread_loop.stop)
            except Exception:
                pass
        logger.info("Async Syslog TCP Collector stopped.")

    def start(self):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.start_async())
        except RuntimeError:
            import threading
            self._thread_loop = asyncio.new_event_loop()
            def _run():
                asyncio.set_event_loop(self._thread_loop)
                self._thread_loop.run_until_complete(self.start_async())
                self._thread_loop.run_forever()
            self._bg_thread = threading.Thread(target=_run, daemon=True)
            self._bg_thread.start()
            import time
            time.sleep(0.05)


class SyslogCollector(BaseConnector):
    """
    Unified Syslog Collector Manager.
    Coordinates both async UDP (5140) and TCP (5141) listeners.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        queue: Optional[IngestionQueue] = None,
        pipeline: Optional[Any] = None,
        event_callback: Optional[Callable] = None,
    ):
        super().__init__(name="Unified Syslog Ingestion Gateway", connector_type="syslog")
        self.udp_collector = SyslogUDPCollector(host=host, port=port or settings.syslog_udp_port, queue=queue, event_callback=event_callback)
        self.tcp_collector = SyslogTCPCollector(host=host, port=settings.syslog_tcp_port, queue=queue, event_callback=event_callback)
        self.pipeline = pipeline
        self.event_callback = event_callback

    async def start_async(self) -> None:
        self.is_running = True
        self.started_at = datetime.now(timezone.utc).isoformat()
        if settings.syslog_udp_enabled:
            await self.udp_collector.start_async()
        if settings.syslog_tcp_enabled:
            await self.tcp_collector.start_async()
            
    def start(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.start_async())
        except RuntimeError:
            if settings.syslog_udp_enabled:
                self.udp_collector.start()
            if settings.syslog_tcp_enabled:
                self.tcp_collector.start()
            self.is_running = True
            self.started_at = datetime.now(timezone.utc).isoformat()

    def stop(self) -> None:
        self.is_running = False
        self.udp_collector.stop()
        self.tcp_collector.stop()

    @property
    def total_received(self) -> int:
        return self.udp_collector.total_received + self.tcp_collector.total_received
        
    @total_received.setter
    def total_received(self, val: int) -> None:
        pass

    @property
    def total_processed(self) -> int:
        return self.udp_collector.total_processed + self.tcp_collector.total_processed
        
    @total_processed.setter
    def total_processed(self, val: int) -> None:
        pass

    @property
    def total_errors(self) -> int:
        return self.udp_collector.total_errors + self.tcp_collector.total_errors
        
    @total_errors.setter
    def total_errors(self, val: int) -> None:
        pass

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "is_running": self.is_running,
            "status": "RUNNING" if self.is_running else "STOPPED",
            "udp_listener": self.udp_collector.get_status(),
            "tcp_listener": self.tcp_collector.get_status(),
            "tls_architecture": {
                "port": settings.syslog_tls_port,
                "status": "PLANNED / OPTIONAL" if not settings.syslog_tls_enabled else "ACTIVE",
                "description": "TLS architecture supported; UDP (5140) & TCP (5141) active in prototype",
            },
            "total_received": self.total_received,
            "total_processed": self.total_processed,
            "total_errors": self.total_errors,
            "current_eps": self.udp_collector.calculate_current_eps() + self.tcp_collector.calculate_current_eps(),
        }

    @property
    def port(self) -> int:
        return getattr(self.udp_collector, "port", settings.syslog_udp_port)

    @port.setter
    def port(self, val: int) -> None:
        if hasattr(self, "udp_collector"):
            self.udp_collector.port = val
