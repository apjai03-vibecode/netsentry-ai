"""Feature extraction for IKE/IPsec VPN sessions."""
from typing import Any, Dict, List, Union
import numpy as np

FEATURE_NAMES = [
    "ike_version",
    "is_aggressive_mode",
    "packet_count",
    "esp_packet_count",
    "dh_group_security_bits",
    "cipher_security_score",
    "integrity_security_score",
    "prf_security_score",
    "has_pfs",
    "auth_method_score",
    "handshake_complete",
    "downgrade_signal",
]

# Estimated symmetric security strength (bits) per NIST SP 800-57
DH_SECURITY_BITS_MAP = {
    1: 64.0,   # 768-bit MODP
    2: 80.0,   # 1024-bit MODP
    5: 96.0,   # 1536-bit MODP
    14: 112.0, # 2048-bit MODP
    15: 128.0, # 3072-bit MODP
    16: 192.0, # 4096-bit MODP
    17: 256.0, # 6144-bit MODP
    18: 256.0, # 8192-bit MODP
    19: 128.0, # 256-bit ECP (NIST P-256)
    20: 192.0, # 384-bit ECP (NIST P-384)
    21: 256.0, # 521-bit ECP (NIST P-521)
    31: 128.0, # Curve25519
    32: 224.0, # Curve448
}


def _extract(session_data: Any, key: str, default: Any = None) -> Any:
    """Helper to extract attribute from dict or object safely."""
    if isinstance(session_data, dict):
        return session_data.get(key, default)
    return getattr(session_data, key, default)


def extract_features_from_session(session_data: Any) -> np.ndarray:
    """
    Extracts a 12-dimensional numerical feature vector from a VPN session:
    [
        ike_version,
        is_aggressive_mode,
        packet_count,
        esp_packet_count,
        dh_group_security_bits,
        cipher_security_score,
        integrity_security_score,
        prf_security_score,
        has_pfs,
        auth_method_score,
        handshake_complete,
        downgrade_signal
    ]
    """
    ike_version = float(_extract(session_data, "ike_version", 2) or 2)

    exchange_types = _extract(session_data, "exchange_types", []) or []
    exchange_type = str(_extract(session_data, "exchange_type", "") or "")
    if isinstance(exchange_types, str):
        exchange_types = [x.strip() for x in exchange_types.split(",") if x.strip()]
    all_exchanges = [e.upper() for e in ([exchange_type] + exchange_types) if e]

    is_aggressive = 1.0 if any("AGGRESSIVE" in e for e in all_exchanges) else 0.0
    packet_count = float(_extract(session_data, "packet_count", 0) or 0)
    esp_count = float(_extract(session_data, "esp_packets", 0) or 0)

    # Diffie-Hellman security bits
    dh_num = _extract(session_data, "dh_group_num")
    dh_str = str(_extract(session_data, "dh_group", "") or "").upper()
    if dh_num and dh_num in DH_SECURITY_BITS_MAP:
        dh_bits = DH_SECURITY_BITS_MAP[dh_num]
    elif "GROUP 1 (" in dh_str or "768-BIT" in dh_str:
        dh_bits = 64.0
    elif "GROUP 2 (" in dh_str or "1024-BIT" in dh_str:
        dh_bits = 80.0
    elif "GROUP 5 (" in dh_str or "1536-BIT" in dh_str:
        dh_bits = 96.0
    elif "GROUP 14" in dh_str or "2048-BIT" in dh_str:
        dh_bits = 112.0
    elif "GROUP 19" in dh_str or "256-BIT" in dh_str or "CURVE25519" in dh_str:
        dh_bits = 128.0
    elif "GROUP 20" in dh_str or "384-BIT" in dh_str:
        dh_bits = 192.0
    elif "GROUP 21" in dh_str:
        dh_bits = 256.0
    else:
        dh_bits = 112.0  # Conservative default

    # Cipher security score
    cipher = str(_extract(session_data, "cipher", "") or "").upper()
    if "NULL" in cipher:
        cipher_score = 0.0
    elif "DES" in cipher and "3DES" not in cipher:
        cipher_score = 1.0
    elif "3DES" in cipher:
        cipher_score = 2.0
    elif "AES-CBC-128" in cipher or "AES-128-CBC" in cipher:
        cipher_score = 3.0
    elif "AES-CBC-256" in cipher or "AES-256-CBC" in cipher:
        cipher_score = 4.0
    elif "AES-GCM-128" in cipher:
        cipher_score = 5.0
    elif "AES-GCM-256" in cipher or "CHACHA20" in cipher:
        cipher_score = 6.0
    elif "AES" in cipher:
        cipher_score = 4.0
    else:
        cipher_score = 3.0

    # Integrity security score
    integ = str(_extract(session_data, "integrity_algo", "") or "").upper()
    if "MD5" in integ:
        integ_score = 1.0
    elif "SHA1" in integ or "SHA-1" in integ:
        integ_score = 2.0
    elif "SHA2-256" in integ or "SHA256" in integ:
        integ_score = 3.0
    elif "SHA2-384" in integ or "SHA2-512" in integ or "GCM" in cipher:
        integ_score = 4.0
    else:
        integ_score = 3.0

    # PRF security score
    prf = str(_extract(session_data, "prf_algo", "") or "").upper()
    if "MD5" in prf:
        prf_score = 1.0
    elif "SHA1" in prf or "SHA-1" in prf:
        prf_score = 2.0
    elif "SHA2-256" in prf or "SHA256" in prf:
        prf_score = 3.0
    elif "SHA2-384" in prf or "SHA2-512" in prf:
        prf_score = 4.0
    else:
        prf_score = 3.0

    # PFS
    pfs_enabled = 1.0 if _extract(session_data, "pfs_enabled", False) else 0.0

    # Auth method score
    auth = str(_extract(session_data, "auth_method", "") or "").upper()
    if "PSK" in auth or "PRE-SHARED" in auth:
        auth_score = 1.0
    elif "RSA" in auth or "SIGNATURE" in auth or "CERT" in auth:
        auth_score = 2.0
    else:
        auth_score = 1.0

    # Handshake completion
    if ike_version == 2:
        has_init = any("INIT" in e for e in all_exchanges)
        has_auth = any("AUTH" in e for e in all_exchanges)
        handshake_complete = 1.0 if (has_init and has_auth) else 0.0
    else:
        if is_aggressive:
            handshake_complete = 1.0 if packet_count >= 3 else 0.0
        else:
            handshake_complete = 1.0 if (packet_count >= 6 or any("QUICK" in e for e in all_exchanges)) else 0.0

    # Downgrade signal
    has_v1 = any("MAIN" in e or "AGGRESSIVE" in e for e in all_exchanges)
    has_v2 = any("INIT" in e or "AUTH" in e for e in all_exchanges)
    downgrade_signal = 1.0 if (has_v1 and has_v2) else 0.0

    return np.array([
        ike_version,
        is_aggressive,
        packet_count,
        esp_count,
        dh_bits,
        cipher_score,
        integ_score,
        prf_score,
        pfs_enabled,
        auth_score,
        handshake_complete,
        downgrade_signal,
    ], dtype=np.float32)


def extract_features_batch(sessions: List[Any]) -> np.ndarray:
    """Extract features for a list of sessions into a 2D numpy array (N, 12)."""
    if not sessions:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)
    return np.vstack([extract_features_from_session(s) for s in sessions])
