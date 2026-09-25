"""Flow-level statistical feature extraction for encrypted IPsec/ESP traffic classification.
Defines and extracts exactly 14 documented behavioral features.
"""
from typing import Any, Dict, List, Optional
import numpy as np

FLOW_FEATURE_NAMES = [
    "packet_count",               # 1. Total packets in flow
    "bytes_sent",                 # 2. Total uplink payload bytes (client -> gateway)
    "bytes_received",             # 3. Total downlink payload bytes (gateway -> client)
    "mean_packet_size",           # 4. Average packet length in bytes
    "packet_size_variance",       # 5. Statistical variance of packet sizes
    "min_packet_size",            # 6. Minimum packet size in bytes
    "max_packet_size",            # 7. Maximum packet size in bytes
    "packets_per_sec",            # 8. Average packet rate (pps)
    "bytes_per_sec",              # 9. Average data throughput (Bps)
    "duration_seconds",           # 10. Total duration of flow in seconds
    "mean_inter_arrival_time",    # 11. Mean time delta between consecutive packets (s)
    "var_inter_arrival_time",     # 12. Variance of inter-arrival time deltas (jitter proxy)
    "downlink_uplink_ratio",      # 13. Ratio of bytes received vs. bytes sent
    "burst_factor",               # 14. Ratio of max packet size relative to mean packet size
]


def extract_14_flow_features(
    packets: List[Dict[str, Any]],
    client_ip: Optional[str] = None
) -> np.ndarray:
    """
    Extracts the exactly 14 documented statistical features from a packet list.
    Each packet in `packets` is a dict with:
      - 'timestamp': float
      - 'size': int
      - 'src_ip': str (optional, to determine direction)
      - 'dst_ip': str (optional)
      - 'direction': 'uplink' or 'downlink' (optional)
    """
    if not packets:
        return np.zeros(len(FLOW_FEATURE_NAMES), dtype=np.float32)

    packet_count = len(packets)
    sizes = []
    timestamps = []
    bytes_sent = 0
    bytes_received = 0

    for p in packets:
        sz = int(p.get("size", p.get("size_bytes", 0)))
        sizes.append(sz)
        ts = float(p.get("timestamp", p.get("time", 0.0)))
        timestamps.append(ts)

        direction = p.get("direction")
        if direction:
            if direction == "downlink":
                bytes_received += sz
            else:
                bytes_sent += sz
        elif client_ip and p.get("src_ip"):
            if p["src_ip"] == client_ip:
                bytes_sent += sz
            else:
                bytes_received += sz
        else:
            # Fallback assumption if direction is completely unknown
            bytes_received += sz

    # Sort timestamps to calculate true IATs
    timestamps.sort()
    t_start = timestamps[0]
    t_end = timestamps[-1]
    duration = max(0.001, t_end - t_start)

    iats = []
    for i in range(1, len(timestamps)):
        dt = max(0.0, timestamps[i] - timestamps[i - 1])
        iats.append(dt)

    mean_sz = float(np.mean(sizes)) if sizes else 0.0
    var_sz = float(np.var(sizes)) if sizes else 0.0
    min_sz = float(np.min(sizes)) if sizes else 0.0
    max_sz = float(np.max(sizes)) if sizes else 0.0

    pps = float(packet_count / duration)
    bps = float((bytes_sent + bytes_received) / duration)

    mean_iat = float(np.mean(iats)) if iats else 0.0
    var_iat = float(np.var(iats)) if iats else 0.0

    down_up_ratio = float(bytes_received / max(1, bytes_sent))
    burst_factor = float(max_sz / max(1.0, mean_sz))

    return np.array([
        float(packet_count),
        float(bytes_sent),
        float(bytes_received),
        round(mean_sz, 2),
        round(var_sz, 2),
        round(min_sz, 2),
        round(max_sz, 2),
        round(pps, 2),
        round(bps, 2),
        round(duration, 4),
        round(mean_iat, 4),
        round(var_iat, 6),
        round(down_up_ratio, 2),
        round(burst_factor, 2),
    ], dtype=np.float32)


def flow_stats_to_vector(stats_dict: Dict[str, Any]) -> np.ndarray:
    """Helper to convert a dictionary with stats into the 14-dim numpy feature vector."""
    return np.array([
        float(stats_dict.get("packet_count", 0)),
        float(stats_dict.get("bytes_sent", 0)),
        float(stats_dict.get("bytes_received", 0)),
        float(stats_dict.get("mean_packet_size", 0.0)),
        float(stats_dict.get("packet_size_variance", 0.0)),
        float(stats_dict.get("min_packet_size", 0.0)),
        float(stats_dict.get("max_packet_size", 0.0)),
        float(stats_dict.get("packets_per_sec", 0.0)),
        float(stats_dict.get("bytes_per_sec", 0.0)),
        float(stats_dict.get("duration_seconds", 0.0)),
        float(stats_dict.get("mean_inter_arrival_time", 0.0)),
        float(stats_dict.get("var_inter_arrival_time", 0.0)),
        float(stats_dict.get("downlink_uplink_ratio", 0.0)),
        float(stats_dict.get("burst_factor", 0.0)),
    ], dtype=np.float32)


class FlowFeaturesResult:
    """Encapsulates the 14 extracted flow features with dictionary and vector conversion."""
    def __init__(self, vector: np.ndarray, names: List[str]):
        self.vector = vector
        self.names = names

    def to_vector(self) -> List[float]:
        return [float(x) for x in self.vector]

    def to_dict(self) -> Dict[str, float]:
        return {name: float(val) for name, val in zip(self.names, self.vector)}


class FlowFeatureExtractor:
    """Extracts exactly 14 flow features from raw packet series or packet dict lists."""

    @classmethod
    def extract(
        cls,
        packet_sizes: Optional[List[int]] = None,
        packet_times: Optional[List[float]] = None,
        flow_duration: Optional[float] = None,
        flow_bytes: Optional[int] = None,
        packet_count: Optional[int] = None,
        packets: Optional[List[Dict[str, Any]]] = None,
    ) -> FlowFeaturesResult:
        """Extract the documented 14 flow features from various input representations."""
        if packets:
            vec = extract_14_flow_features(packets)
        else:
            p_sizes = packet_sizes or [128, 512, 1024, 64]
            p_times = packet_times or [0.0, 0.02, 0.05, 0.10]
            p_dicts = []
            for i in range(len(p_sizes)):
                t = p_times[i] if i < len(p_times) else (0.01 * i)
                p_dicts.append({"size": p_sizes[i], "timestamp": t})
            vec = extract_14_flow_features(p_dicts)

        return FlowFeaturesResult(vec, FLOW_FEATURE_NAMES)

