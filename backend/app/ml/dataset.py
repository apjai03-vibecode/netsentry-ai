"""Dataset generator and testbed capture simulator for VPN session ML training."""
from typing import List, Tuple
import numpy as np
from app.ml.features import FEATURE_NAMES, extract_features_batch


def generate_labeled_vpn_dataset(seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates a balanced, realistic labeled testbed dataset of VPN session metadata:
    - Label 1: Vulnerable / High Risk (weak DH, deprecated ciphers, weak integrity, aggressive mode, truncated)
    - Label 0: Secure / Benign (IKEv2, AES-GCM, DH 14/19/20, PFS, completed handshake)
    """
    np.random.seed(seed)
    sessions: List[dict] = []
    labels: List[int] = []

    # -------------------------------------------------------------
    # 1. Vulnerable Class (Label 1) - ~250 samples
    # -------------------------------------------------------------
    vulnerable_templates = [
        # Weak DH 1 / 2
        {"ike_version": 2, "dh_group_num": 2, "dh_group": "Group 2 (1024-bit)", "cipher": "AES-CBC-128", "integrity_algo": "AUTH_HMAC_SHA1_96", "prf_algo": "PRF_HMAC_SHA1", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 20, "pfs_enabled": False, "auth_method": "PSK"},
        {"ike_version": 2, "dh_group_num": 1, "dh_group": "Group 1 (768-bit)", "cipher": "3DES-CBC", "integrity_algo": "AUTH_HMAC_MD5_96", "prf_algo": "PRF_HMAC_MD5", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 15, "pfs_enabled": False, "auth_method": "PSK"},
        {"ike_version": 2, "dh_group_num": 5, "dh_group": "Group 5 (1536-bit)", "cipher": "AES-CBC-128", "integrity_algo": "AUTH_HMAC_SHA1_96", "prf_algo": "PRF_HMAC_SHA1", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 10, "pfs_enabled": True, "auth_method": "PSK"},

        # Deprecated 3DES / DES / NULL
        {"ike_version": 2, "dh_group_num": 14, "dh_group": "Group 14 (2048-bit)", "cipher": "3DES-CBC", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 50, "pfs_enabled": False, "auth_method": "PSK"},
        {"ike_version": 1, "dh_group_num": 2, "dh_group": "Group 2", "cipher": "DES-CBC", "integrity_algo": "AUTH_HMAC_MD5_96", "prf_algo": "PRF_HMAC_MD5", "exchange_types": ["Main Mode"], "packet_count": 6, "esp_packets": 30, "pfs_enabled": False, "auth_method": "PSK"},
        {"ike_version": 2, "dh_group_num": 14, "dh_group": "Group 14", "cipher": "NULL", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 10, "pfs_enabled": False, "auth_method": "PSK"},

        # IKEv1 Aggressive Mode
        {"ike_version": 1, "dh_group_num": 2, "dh_group": "Group 2", "cipher": "AES-CBC-128", "integrity_algo": "AUTH_HMAC_SHA1_96", "prf_algo": "PRF_HMAC_SHA1", "exchange_types": ["Aggressive Mode"], "packet_count": 3, "esp_packets": 25, "pfs_enabled": False, "auth_method": "Pre-Shared Key (PSK)"},
        {"ike_version": 1, "dh_group_num": 5, "dh_group": "Group 5", "cipher": "3DES-CBC", "integrity_algo": "AUTH_HMAC_MD5_96", "prf_algo": "PRF_HMAC_MD5", "exchange_types": ["Aggressive Mode"], "packet_count": 3, "esp_packets": 5, "pfs_enabled": False, "auth_method": "PSK"},

        # Truncated / Incomplete Handshakes
        {"ike_version": 2, "dh_group_num": 14, "dh_group": "Group 14", "cipher": "AES-GCM-256", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT"], "packet_count": 2, "esp_packets": 0, "pfs_enabled": False, "auth_method": "PSK"},
        {"ike_version": 1, "dh_group_num": 2, "dh_group": "Group 2", "cipher": "AES-CBC-128", "integrity_algo": "AUTH_HMAC_SHA1_96", "prf_algo": "PRF_HMAC_SHA1", "exchange_types": ["Main Mode"], "packet_count": 2, "esp_packets": 0, "pfs_enabled": False, "auth_method": "PSK"},

        # Downgrade Signal
        {"ike_version": 2, "dh_group_num": 2, "dh_group": "Group 2", "cipher": "3DES-CBC", "integrity_algo": "AUTH_HMAC_SHA1_96", "prf_algo": "PRF_HMAC_SHA1", "exchange_types": ["IKE_SA_INIT", "Main Mode"], "packet_count": 5, "esp_packets": 0, "pfs_enabled": False, "auth_method": "PSK"},
    ]

    for _ in range(25):
        for tmpl in vulnerable_templates:
            instance = dict(tmpl)
            # Add small random variations to packet counts
            instance["packet_count"] = max(1, instance["packet_count"] + int(np.random.randint(-1, 3)))
            instance["esp_packets"] = max(0, instance["esp_packets"] + int(np.random.randint(-3, 10)))
            sessions.append(instance)
            labels.append(1)

    # -------------------------------------------------------------
    # 2. Secure Class (Label 0) - ~250 samples
    # -------------------------------------------------------------
    secure_templates = [
        {"ike_version": 2, "dh_group_num": 14, "dh_group": "Group 14 (2048-bit)", "cipher": "AES-GCM-256", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 120, "pfs_enabled": True, "auth_method": "RSA Digital Signatures"},
        {"ike_version": 2, "dh_group_num": 19, "dh_group": "Group 19 (256-bit Random ECP)", "cipher": "AES-GCM-256", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 250, "pfs_enabled": True, "auth_method": "RSA Digital Signatures"},
        {"ike_version": 2, "dh_group_num": 20, "dh_group": "Group 20 (384-bit Random ECP)", "cipher": "AES-GCM-256", "integrity_algo": "AUTH_HMAC_SHA2_384_192", "prf_algo": "PRF_HMAC_SHA2_384", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 400, "pfs_enabled": True, "auth_method": "Digital Signature (RFC 7427)"},
        {"ike_version": 2, "dh_group_num": 31, "dh_group": "Curve25519 (RFC 8031)", "cipher": "CHACHA20-POLY1305", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 310, "pfs_enabled": True, "auth_method": "Digital Signature (RFC 7427)"},
        {"ike_version": 2, "dh_group_num": 14, "dh_group": "Group 14 (2048-bit)", "cipher": "AES-CBC-256", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 80, "pfs_enabled": True, "auth_method": "Pre-Shared Key (PSK)"},
        {"ike_version": 2, "dh_group_num": 19, "dh_group": "Group 19 (256-bit Random ECP)", "cipher": "AES-GCM-128", "integrity_algo": "AUTH_HMAC_SHA2_256_128", "prf_algo": "PRF_HMAC_SHA2_256", "exchange_types": ["IKE_SA_INIT", "IKE_AUTH"], "packet_count": 4, "esp_packets": 190, "pfs_enabled": True, "auth_method": "Pre-Shared Key (PSK)"},
    ]

    for _ in range(45):
        for tmpl in secure_templates:
            instance = dict(tmpl)
            instance["packet_count"] = max(4, instance["packet_count"] + int(np.random.randint(-1, 5)))
            instance["esp_packets"] = max(10, instance["esp_packets"] + int(np.random.randint(-20, 50)))
            sessions.append(instance)
            labels.append(0)

    X = extract_features_batch(sessions)
    y = np.array(labels, dtype=np.int32)
    return X, y
