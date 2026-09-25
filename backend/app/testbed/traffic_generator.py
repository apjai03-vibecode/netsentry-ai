"""Traffic Profile & Synthetic Packet Trace Generator for NetSentry Testbed.
Supports Web, VoIP, Video, Messaging, Email, ICMP, and Bulk/Data profiles.
"""
from dataclasses import dataclass, field
import io
import time
from typing import Any, Dict, List, Optional
import numpy as np

# Safe Scapy import
try:
    from scapy.layers.inet import IP, UDP
    from scapy.utils import wrpcap
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class FlowPacket:
    timestamp: float
    direction: str       # 'uplink' (client->gw) or 'downlink' (gw->client)
    size_bytes: int
    protocol: str        # 'ESP' or 'UDP'
    src_ip: str
    dst_ip: str
    spi: str


@dataclass
class TrafficProfile:
    traffic_class: str   # 'Web', 'VoIP', 'Video', 'Messaging-like', 'Email-like', 'ICMP', 'Bulk/Data'
    description: str
    packet_count: int
    duration_seconds: float
    packets: List[FlowPacket] = field(default_factory=list)
    stats: Dict[str, float] = field(default_factory=dict)


class VPNTrafficProfileGenerator:
    """Generates realistic encrypted traffic flow profiles based on behavioral patterns."""

    PROFILES = {

        "Web": {
            "desc": "Bursty HTTP/HTTPS traffic: small initial requests, large downlink responses, high size variance.",
            "mean_size_up": 240,
            "mean_size_down": 1380,
            "down_up_ratio": 4.5,
            "mean_iat": 0.08,
            "iat_jitter": 0.05,
        },
        "VoIP": {
            "desc": "Constant-bitrate periodic UDP audio: symmetric bidirectional sizes (~160-220 bytes), low jitter, ~20ms interval.",
            "mean_size_up": 180,
            "mean_size_down": 180,
            "down_up_ratio": 1.0,
            "mean_iat": 0.02,
            "iat_jitter": 0.003,
        },
        "Video": {
            "desc": "High-throughput sustained streaming: maximum packet sizes on downlink (~1400-1460 bytes), low uplink ACKs.",
            "mean_size_up": 80,
            "mean_size_down": 1420,
            "down_up_ratio": 8.0,
            "mean_iat": 0.008,
            "iat_jitter": 0.004,
        },
        "Messaging-like": {
            "desc": "Intermittent small message bursts: 100-300 byte packets followed by idle pause intervals.",
            "mean_size_up": 160,
            "mean_size_down": 220,
            "down_up_ratio": 1.4,
            "mean_iat": 0.45,
            "iat_jitter": 0.35,
        },
        "Email-like": {
            "desc": "Periodic IMAP/SMTP sync bursts with mixed payload sizes and idle polling intervals.",
            "mean_size_up": 320,
            "mean_size_down": 850,
            "down_up_ratio": 2.6,
            "mean_iat": 0.15,
            "iat_jitter": 0.10,
        },
        "ICMP": {
            "desc": "Periodic echo request/reply pings: constant uniform size (~84 bytes) and fixed 1.0s interval.",
            "mean_size_up": 84,
            "mean_size_down": 84,
            "down_up_ratio": 1.0,
            "mean_iat": 1.00,
            "iat_jitter": 0.001,
        },
        "Bulk/Data": {
            "desc": "Sustained file transfer: maximum MTU packets (~1460 bytes) with minimal inter-arrival delay.",
            "mean_size_up": 72,
            "mean_size_down": 1460,
            "down_up_ratio": 12.0,
            "mean_iat": 0.003,
            "iat_jitter": 0.001,
        },
    }

    @classmethod
    def generate_flow(
        cls,
        traffic_type: str = "Web",
        num_packets: int = 60,
        start_time: Optional[float] = None,
        client_ip: str = "192.168.1.100",
        gateway_ip: str = "198.51.100.1",
        esp_spi: str = "0x3a4b5c6d",
    ) -> TrafficProfile:
        """Generate a simulated FlowPacket sequence adhering to behavioral parameters."""
        if traffic_type not in cls.PROFILES:
            traffic_type = "Web"

        params = cls.PROFILES[traffic_type]
        base_time = start_time or time.time()
        packets: List[FlowPacket] = []

        cur_time = base_time
        down_ratio = params["down_up_ratio"]
        prob_down = down_ratio / (1.0 + down_ratio)

        bytes_sent = 0
        bytes_recv = 0
        sizes: List[int] = []
        iats: List[float] = []

        for i in range(num_packets):
            is_down = bool(np.random.rand() < prob_down) if i > 0 else False
            direction = "downlink" if is_down else "uplink"

            if is_down:
                mean_sz = params["mean_size_down"]
                src, dst = gateway_ip, client_ip
            else:
                mean_sz = params["mean_size_up"]
                src, dst = client_ip, gateway_ip

            sz = int(np.clip(np.random.normal(mean_sz, mean_sz * 0.15), 64, 1500))
            sizes.append(sz)

            if is_down:
                bytes_recv += sz
            else:
                bytes_sent += sz

            iat = max(0.0005, float(np.random.normal(params["mean_iat"], params["iat_jitter"])))
            if i > 0:
                iats.append(iat)
                cur_time += iat

            packets.append(FlowPacket(
                timestamp=round(cur_time, 4),
                direction=direction,
                size_bytes=sz,
                protocol="ESP",
                src_ip=src,
                dst_ip=dst,
                spi=esp_spi,
            ))

        duration = max(0.001, cur_time - base_time)
        stats = {
            "packet_count": float(num_packets),
            "bytes_sent": float(bytes_sent),
            "bytes_received": float(bytes_recv),
            "mean_packet_size": float(np.mean(sizes)) if sizes else 0.0,
            "packet_size_variance": float(np.var(sizes)) if sizes else 0.0,
            "min_packet_size": float(np.min(sizes)) if sizes else 0.0,
            "max_packet_size": float(np.max(sizes)) if sizes else 0.0,
            "packets_per_sec": round(num_packets / duration, 2),
            "bytes_per_sec": round((bytes_sent + bytes_recv) / duration, 2),
            "duration_seconds": round(duration, 3),
            "mean_inter_arrival_time": float(np.mean(iats)) if iats else 0.0,
            "var_inter_arrival_time": float(np.var(iats)) if iats else 0.0,
            "downlink_uplink_ratio": round(bytes_recv / max(1, bytes_sent), 2),
            "burst_factor": round(float(np.max(sizes) / max(1.0, np.mean(sizes))), 2),
        }

        return TrafficProfile(
            traffic_class=traffic_type,
            description=params["desc"],
            packet_count=num_packets,
            duration_seconds=duration,
            packets=packets,
            stats=stats,
        )

    @classmethod
    def generate_synthetic_pcap_bytes(
        cls,
        traffic_type: str = "Web",
        num_packets: int = 40,
        client_ip: str = "192.168.1.100",
        gateway_ip: str = "198.51.100.1",
        ike_version: int = 2,
    ) -> bytes:
        """Create a valid in-memory binary PCAP containing IKE handshake + ESP traffic."""
        if not SCAPY_AVAILABLE:
            return b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"

        scapy_packets = []
        base_t = time.time() - 10.0

        # Packet 1: IKE_SA_INIT Request
        ike_init_req = (
            b"\x11\x22\x33\x44\x55\x66\x77\x88"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\x00\x78"
            b"\x00\x00\x00\x28\x00\x00\x00\x24\x01\x01\x00\x03\x03\x00\x00\x0c"
            b"\x01\x00\x00\x14\x80\x0e\x01\x00\x03\x00\x00\x08\x02\x00\x00\x05"
            b"\x00\x00\x00\x08\x04\x00\x00\x13"
            + b"\x00" * 48
        )
        pkt1 = IP(src=client_ip, dst=gateway_ip) / UDP(sport=500, dport=500) / Raw(load=ike_init_req)
        pkt1.time = base_t
        scapy_packets.append(pkt1)

        # Packet 2: IKE_SA_INIT Response
        ike_init_resp = (
            b"\x11\x22\x33\x44\x55\x66\x77\x88"
            b"\x99\xaa\xbb\xcc\xdd\xee\xff\x00"
            b"\x21\x20\x22\x20\x00\x00\x00\x00\x00\x00\x00\x78"
            b"\x00\x00\x00\x28\x00\x00\x00\x24\x01\x01\x00\x03\x03\x00\x00\x0c"
            b"\x01\x00\x00\x14\x80\x0e\x01\x00\x03\x00\x00\x08\x02\x00\x00\x05"
            b"\x00\x00\x00\x08\x04\x00\x00\x13"
            + b"\x00" * 48
        )
        pkt2 = IP(src=gateway_ip, dst=client_ip) / UDP(sport=500, dport=500) / Raw(load=ike_init_resp)
        pkt2.time = base_t + 0.015
        scapy_packets.append(pkt2)

        # Packet 3 & 4: IKE_AUTH Exchange
        ike_auth_req = (
            b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"
            b"\x2e\x20\x23\x08\x00\x00\x00\x01\x00\x00\x00\x50"
            + b"\xef" * 52
        )
        pkt3 = IP(src=client_ip, dst=gateway_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + ike_auth_req)
        pkt3.time = base_t + 0.035
        scapy_packets.append(pkt3)

        # Generate Traffic Profile ESP Packets
        profile = cls.generate_flow(
            traffic_type=traffic_type,
            num_packets=num_packets,
            start_time=base_t + 0.10,
            client_ip=client_ip,
            gateway_ip=gateway_ip,
        )

        for fp in profile.packets:
            esp_payload = b"\x3a\x4b\x5c\x6d\x00\x00\x00\x01" + b"\x55" * max(8, fp.size_bytes - 28)
            pkt_esp = IP(src=fp.src_ip, dst=fp.dst_ip, proto=50) / Raw(load=esp_payload)
            pkt_esp.time = fp.timestamp
            scapy_packets.append(pkt_esp)

        import tempfile
        import os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp_path = tmp.name
        try:
            wrpcap(tmp_path, scapy_packets)
            with open(tmp_path, "rb") as f:
                return f.read()
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass


    def generate_pcap(
        self,
        scenario: str = "IKEV2_ESTABLISHED",
        profile: str = "Web",
        packet_count: int = 40,
        anomalous: bool = False,
    ) -> bytes:
        """Instance method for generating synthetic PCAP."""
        # Normalize profile name
        p_name = "Web"
        for key in self.PROFILES:
            if key.lower() in profile.lower():
                p_name = key
                break
        return self.generate_synthetic_pcap_bytes(
            traffic_type=p_name,
            num_packets=packet_count,
        )


SyntheticTrafficGenerator = VPNTrafficProfileGenerator
TRAFFIC_PROFILES = VPNTrafficProfileGenerator.PROFILES
