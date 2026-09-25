"""
Live Capture and Stream Simulation Engine for NetSentry.ai.

Supports two operational modes:
1. Live Sniffer: Direct packet capture via Scapy AsyncSniffer on physical/virtual interfaces (promiscuous mode).
2. Stream Simulation: Real-time packet replay simulator that emits synthetic or PCAP packets at controlled
   packet rates (pps) into the FSM and protocol analyzer without requiring root/promiscuous privileges.
"""

import asyncio
from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from app.parsers.ike_parser import IKEParser, ParsedVPNSessionData
from app.engines.fsm_engine import IKEStateMachineTracker
from app.testbed.traffic_generator import SyntheticTrafficGenerator

logger = logging.getLogger(__name__)


class LivePacketRecord:
    """Represents a live or replayed packet in the live stream."""
    def __init__(
        self,
        index: int,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        length: int,
        summary: str,
        info: Dict[str, Any],
    ):
        self.index = index
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.length = length
        self.summary = summary
        self.info = info

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "length": self.length,
            "summary": self.summary,
            "info": self.info,
        }


class LiveCaptureEngine:
    """Manages live sniffing and stream simulation with real-time state tracking."""

    _instance: Optional["LiveCaptureEngine"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LiveCaptureEngine, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.is_active: bool = False
        self.mode: str = "IDLE"  # IDLE, LIVE_SNIFFER, STREAM_SIMULATION
        self.packet_buffer: List[Dict[str, Any]] = []
        self.max_buffer_size: int = 1000
        self.packets_captured: int = 0
        self.start_time: Optional[float] = None
        self.fsm = IKEStateMachineTracker()
        self.sessions: Dict[str, ParsedVPNSessionData] = {}
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._sniffer = None

    def get_status(self) -> Dict[str, Any]:
        """Return the current status of live capture or simulation."""
        elapsed = time.time() - self.start_time if (self.is_active and self.start_time) else 0.0
        return {
            "is_active": self.is_active,
            "mode": self.mode,
            "packets_captured": self.packets_captured,
            "elapsed_seconds": round(elapsed, 1),
            "recent_packets": self.packet_buffer[-50:],
            "fsm_summary": self.fsm.get_summary(),
            "active_sessions_count": len(self.sessions),
        }

    def stop(self) -> Dict[str, Any]:
        """Stop active capture or simulation cleanly."""
        self._stop_event.set()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning(f"Error stopping sniffer: {e}")
            self._sniffer = None

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

        self.is_active = False
        final_mode = self.mode
        self.mode = "IDLE"
        logger.info(f"Live capture stopped. Total packets: {self.packets_captured}")
        return {
            "status": "STOPPED",
            "previous_mode": final_mode,
            "total_packets": self.packets_captured,
        }

    def start_simulation(
        self,
        scenario: str = "IKEV2_ESTABLISHED",
        packet_count: int = 50,
        rate_pps: float = 5.0,
    ) -> Dict[str, Any]:
        """Start non-blocking stream simulation at specified packet rate."""
        if self.is_active:
            self.stop()

        self.reset()
        self.is_active = True
        self.mode = "STREAM_SIMULATION"
        self.start_time = time.time()
        self._stop_event.clear()

        self._worker_thread = threading.Thread(
            target=self._run_simulation,
            args=(scenario, packet_count, rate_pps),
            daemon=True,
        )
        self._worker_thread.start()

        return {
            "status": "STARTED",
            "mode": self.mode,
            "scenario": scenario,
            "rate_pps": rate_pps,
            "target_packets": packet_count,
        }

    def _run_simulation(self, scenario: str, packet_count: int, rate_pps: float):
        """Worker thread for streaming simulation."""
        logger.info(f"Stream simulation started: {scenario} at {rate_pps} pps")
        interval = 1.0 / max(rate_pps, 0.5)

        # Generate stream sequence
        seq = self._build_scenario_packet_sequence(scenario, packet_count)

        for idx, pkt in enumerate(seq):
            if self._stop_event.is_set():
                break

            # Ingest packet into FSM & buffer
            self.packets_captured += 1
            record = {
                "index": self.packets_captured,
                "timestamp": round(time.time(), 4),
                "src_ip": pkt.get("src_ip", "192.168.1.100"),
                "dst_ip": pkt.get("dst_ip", "198.51.100.1"),
                "protocol": pkt.get("protocol", "UDP/500"),
                "length": pkt.get("length", 128),
                "summary": pkt.get("summary", "IKEv2 Packet"),
                "info": pkt.get("info", {}),
            }

            self.packet_buffer.append(record)
            if len(self.packet_buffer) > self.max_buffer_size:
                self.packet_buffer.pop(0)

            # Advance FSM
            ike_ver = pkt.get("ike_version", 2)
            exch = pkt.get("exchange_type", "IKE_SA_INIT")
            msg_id = pkt.get("msg_id", 0)
            is_resp = pkt.get("is_response", False)
            is_init = pkt.get("is_initiator", True)
            self.fsm.process_packet(ike_ver, exch, msg_id, is_resp, is_init)

            time.sleep(interval)

        self.is_active = False
        self.mode = "IDLE"
        logger.info(f"Simulation ended. Completed {self.packets_captured} packets.")

    def _build_scenario_packet_sequence(self, scenario: str, total_count: int) -> List[Dict[str, Any]]:
        """Generate realistic sequence of packets for simulation."""
        seq = []

        if "IKEV1" in scenario.upper():
            # IKEv1 Main Mode: 6 packets followed by ESP
            for i in range(1, min(7, total_count + 1)):
                is_resp = (i % 2 == 0)
                seq.append({
                    "src_ip": "198.51.100.1" if is_resp else "192.168.1.100",
                    "dst_ip": "192.168.1.100" if is_resp else "198.51.100.1",
                    "protocol": "UDP/500",
                    "length": 256 + (i * 32),
                    "summary": f"IKEv1 Main Mode Msg {i}/6",
                    "ike_version": 1,
                    "exchange_type": "Identity Protection (Main Mode)",
                    "msg_id": 0,
                    "is_response": is_resp,
                    "is_initiator": not is_resp,
                    "info": {"phase": 1, "packet_num": i},
                })
        else:
            # IKEv2 Handshake: SA_INIT req (1), SA_INIT resp (2), AUTH req (3), AUTH resp (4)
            handshake = [
                ("IKE_SA_INIT", 0, False, True, 340, "IKE_SA_INIT Request (Proposal: AES-GCM-256, DH 14)"),
                ("IKE_SA_INIT", 0, True, False, 340, "IKE_SA_INIT Response (Accepted: AES-GCM-256, DH 14)"),
                ("IKE_AUTH", 1, False, True, 480, "IKE_AUTH Request (Encrypted ID & Cert)"),
                ("IKE_AUTH", 1, True, False, 480, "IKE_AUTH Response (Mutual Auth Complete)"),
            ]
            for exch, mid, is_resp, is_init, length, desc in handshake:
                if len(seq) >= total_count:
                    break
                seq.append({
                    "src_ip": "198.51.100.1" if is_resp else "192.168.1.100",
                    "dst_ip": "192.168.1.100" if is_resp else "198.51.100.1",
                    "protocol": "UDP/4500" if "AUTH" in exch else "UDP/500",
                    "length": length,
                    "summary": desc,
                    "ike_version": 2,
                    "exchange_type": exch,
                    "msg_id": mid,
                    "is_response": is_resp,
                    "is_initiator": is_init,
                    "info": {"exchange": exch, "msg_id": mid},
                })

        # Fill remaining packet budget with encrypted ESP data packets
        rem = total_count - len(seq)
        for i in range(rem):
            is_reverse = (i % 2 == 1)
            seq.append({
                "src_ip": "198.51.100.1" if is_reverse else "192.168.1.100",
                "dst_ip": "192.168.1.100" if is_reverse else "198.51.100.1",
                "protocol": "ESP (Proto 50)",
                "length": 80 + (i * 17) % 1200,
                "summary": f"Encrypted ESP Payload (SPI: 0x{1000+i:04x}, Seq: {i+1})",
                "ike_version": 2,
                "exchange_type": "ESP_DATA",
                "msg_id": i + 1,
                "is_response": is_reverse,
                "is_initiator": not is_reverse,
                "info": {"esp_seq": i + 1, "encrypted": True},
            })

        return seq

    def reset(self):
        """Reset internal buffers and FSM."""
        self.packet_buffer.clear()
        self.packets_captured = 0
        self.sessions.clear()
        self.fsm.reset()
