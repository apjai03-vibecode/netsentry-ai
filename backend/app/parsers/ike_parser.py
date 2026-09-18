"""IKEv1 and IKEv2 Protocol Parser using Scapy and DPKT."""
import io
import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import dpkt
from scapy.layers.inet import IP, UDP
from scapy.utils import rdpcap, PcapReader

logger = logging.getLogger(__name__)

# RFC 7296 & RFC 4301 Mappings
IKE_EXCHANGE_TYPES_V2 = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IKE_EXCHANGE_TYPES_V1 = {
    1: "Base",
    2: "Identity Protection (Main Mode)",
    3: "Authentication Only",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
}

TRANSFORM_ENCR = {
    1: "DES-IV64",
    2: "DES-CBC",
    3: "3DES-CBC",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "BLOWFISH",
    8: "3IDEA",
    9: "DES-IV32",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
    28: "CHACHA20-POLY1305",
}

TRANSFORM_PRF = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
}

TRANSFORM_INTEG = {
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    6: "AUTH_HMAC_MD5_128",
    7: "AUTH_HMAC_SHA1_160",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

TRANSFORM_DH = {
    1: "Group 1 (768-bit MODP - Insecure)",
    2: "Group 2 (1024-bit MODP - Insecure)",
    5: "Group 5 (1536-bit MODP - Deprecated)",
    14: "Group 14 (2048-bit MODP - Standard)",
    15: "Group 15 (3072-bit MODP)",
    16: "Group 16 (4096-bit MODP)",
    17: "Group 17 (6144-bit MODP)",
    18: "Group 18 (8192-bit MODP)",
    19: "Group 19 (256-bit Random ECP)",
    20: "Group 20 (384-bit Random ECP)",
    21: "Group 21 (521-bit Random ECP)",
    31: "Curve25519 (RFC 8031)",
    32: "Curve448 (RFC 8031)",
}

AUTH_METHODS = {
    1: "Pre-Shared Key (PSK)",
    2: "DSS Signatures",
    3: "RSA Digital Signatures",
    4: "Encryption with RSA",
    14: "Digital Signature (RFC 7427)",
}


@dataclass
class ParsedIKEExchange:
    """Represents a single parsed IKE packet/exchange."""
    ike_version: int
    exchange_type_code: int
    exchange_type_name: str
    initiator_spi: str
    responder_spi: str
    msg_id: int
    is_response: bool
    is_initiator: bool
    next_payload: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ciphers: List[str] = field(default_factory=list)
    dh_groups: List[Tuple[int, str]] = field(default_factory=list)
    integrity_algos: List[str] = field(default_factory=list)
    prf_algos: List[str] = field(default_factory=list)
    auth_methods: List[str] = field(default_factory=list)
    raw_payload_length: int = 0


@dataclass
class ParsedVPNSessionData:
    """Aggregated VPN session metadata parsed across multiple packets."""
    session_key: str
    ike_version: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    initiator_spi: str
    responder_spi: str
    exchange_types: List[str] = field(default_factory=list)
    cipher: Optional[str] = None
    dh_group: Optional[str] = None
    dh_group_num: Optional[int] = None
    integrity_algo: Optional[str] = None
    prf_algo: Optional[str] = None
    auth_method: Optional[str] = None
    pfs_enabled: bool = False
    packet_count: int = 0
    esp_packets: int = 0
    esp_spi: Optional[str] = None
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


class IKEParser:
    """High-performance parser for IKEv1/IKEv2 handshakes and IPsec sessions."""

    @staticmethod
    def parse_ike_header(payload: bytes) -> Optional[Dict[str, Any]]:
        """Parse raw 28-byte IKE header directly from bytes."""
        if len(payload) < 28:
            return None

        # Check for NAT-Traversal 4-byte Non-ESP marker (0x00000000) on port 4500
        if payload.startswith(b"\x00\x00\x00\x00") and len(payload) >= 32:
            payload = payload[4:]

        if len(payload) < 28:
            return None

        init_spi, resp_spi, next_payload, version_byte, exch_type, flags, msg_id, length = struct.unpack(
            "!8s8sBBBBII", payload[:28]
        )

        major_ver = (version_byte >> 4) & 0x0F
        minor_ver = version_byte & 0x0F
        ike_version = 1 if major_ver == 1 else 2

        is_response = bool(flags & 0x20)
        is_initiator = bool(flags & 0x08)

        if ike_version == 1:
            exch_name = IKE_EXCHANGE_TYPES_V1.get(exch_type, f"IKEv1-Unknown({exch_type})")
        else:
            exch_name = IKE_EXCHANGE_TYPES_V2.get(exch_type, f"IKEv2-Unknown({exch_type})")

        return {
            "initiator_spi": init_spi.hex(),
            "responder_spi": resp_spi.hex(),
            "next_payload": next_payload,
            "major_version": major_ver,
            "minor_version": minor_ver,
            "ike_version": ike_version,
            "exchange_type": exch_type,
            "exchange_name": exch_name,
            "flags": flags,
            "is_response": is_response,
            "is_initiator": is_initiator,
            "msg_id": msg_id,
            "length": length,
            "payload_data": payload[28:],
        }

    @staticmethod
    def parse_v2_transforms(sa_data: bytes) -> Dict[str, List[Any]]:
        """Walk IKEv2 SA payload proposals and extract transform attributes."""
        extracted: Dict[str, List[Any]] = {
            "encr": [],
            "prf": [],
            "integ": [],
            "dh": [],
        }
        # Check if sa_data includes the 4-byte generic payload header
        if len(sa_data) >= 4:
            _, _, payload_len = struct.unpack("!BBH", sa_data[:4])
            if payload_len == len(sa_data) or (payload_len > 4 and payload_len <= len(sa_data) + 4):
                sa_data = sa_data[4:]

        offset = 0
        while offset + 4 <= len(sa_data):
            # Proposal header: next_payload(1), reserved(1), proposal_len(2), prop_num(1), proto_id(1), spi_size(1), num_transforms(1)
            if offset + 8 > len(sa_data):
                break
            last_or_more, _, prop_len, prop_num, proto_id, spi_size, num_trans = struct.unpack(
                "!BBHBBBB", sa_data[offset:offset+8]
            )
            trans_offset = offset + 8 + spi_size
            prop_end = offset + prop_len

            for _ in range(num_trans):
                if trans_offset + 8 > len(sa_data) or trans_offset + 8 > prop_end:
                    break
                t_last, _, t_len, t_type, _, t_id = struct.unpack(
                    "!BBHBBH", sa_data[trans_offset:trans_offset+8]
                )
                
                # Check for key length attribute (Type 14)
                attr_offset = trans_offset + 8
                key_len = None
                while attr_offset + 4 <= trans_offset + t_len:
                    attr_type, attr_val = struct.unpack("!HH", sa_data[attr_offset:attr_offset+4])
                    if (attr_type & 0x7FFF) == 14:  # Key Length
                        key_len = attr_val
                    attr_offset += 4

                if t_type == 1:  # Encryption (ENCR)
                    name = TRANSFORM_ENCR.get(t_id, f"ENCR_{t_id}")
                    if key_len:
                        name = f"{name}-{key_len}"
                    extracted["encr"].append(name)
                elif t_type == 2:  # PRF
                    name = TRANSFORM_PRF.get(t_id, f"PRF_{t_id}")
                    extracted["prf"].append(name)
                elif t_type == 3:  # Integrity (INTEG)
                    name = TRANSFORM_INTEG.get(t_id, f"INTEG_{t_id}")
                    extracted["integ"].append(name)
                elif t_type == 4:  # Diffie-Hellman Group
                    dh_name = TRANSFORM_DH.get(t_id, f"Group {t_id}")
                    extracted["dh"].append((t_id, dh_name))

                trans_offset += max(t_len, 8)

            if last_or_more == 0:
                break
            offset = prop_end

        return extracted

    @staticmethod
    def parse_v1_transforms(sa_data: bytes) -> Dict[str, List[Any]]:
        """Walk IKEv1 SA payload proposals and extract transform attributes."""
        extracted: Dict[str, List[Any]] = {
            "encr": [],
            "prf": [],
            "integ": [],
            "dh": [],
            "auth": [],
        }
        # In IKEv1, attributes are packed inside ISAKMP Transform payloads
        offset = 0
        while offset + 8 <= len(sa_data):
            next_p, _, p_len = struct.unpack("!BBH", sa_data[offset:offset+4])
            if p_len == 0 or offset + p_len > len(sa_data):
                break
            chunk = sa_data[offset:offset+p_len]
            # Scan chunk for basic IKEv1 attribute pairs (Type, Value)
            attr_ptr = 8
            while attr_ptr + 4 <= len(chunk):
                attr_t, attr_v = struct.unpack("!HH", chunk[attr_ptr:attr_ptr+4])
                is_tv = bool(attr_t & 0x8000)
                attr_num = attr_t & 0x7FFF
                
                if is_tv:
                    val = attr_v
                    attr_ptr += 4
                else:
                    val_len = attr_v
                    if attr_ptr + 4 + val_len <= len(chunk):
                        val = int.from_bytes(chunk[attr_ptr+4:attr_ptr+4+val_len], "big")
                    else:
                        val = 0
                    attr_ptr += 4 + val_len

                if attr_num == 1:  # Encryption Algorithm
                    extracted["encr"].append(TRANSFORM_ENCR.get(val, f"ENCR_{val}"))
                elif attr_num == 2:  # Hash Algorithm (Integrity)
                    extracted["integ"].append(TRANSFORM_INTEG.get(val, f"HASH_{val}"))
                elif attr_num == 3:  # Authentication Method
                    extracted["auth"].append(AUTH_METHODS.get(val, f"AUTH_{val}"))
                elif attr_num == 4:  # Group Description (DH)
                    extracted["dh"].append((val, TRANSFORM_DH.get(val, f"Group {val}")))

            if next_p == 0:
                break
            offset += p_len

        return extracted

    @classmethod
    def parse_packet_bytes(
        cls,
        data: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int
    ) -> Optional[ParsedIKEExchange]:
        """Parse raw UDP payload bytes into a ParsedIKEExchange object."""
        header = cls.parse_ike_header(data)
        if not header:
            return None

        ike_ver = header["ike_version"]
        payload_data = header["payload_data"]

        ciphers: List[str] = []
        dh_groups: List[Tuple[int, str]] = []
        integ_algos: List[str] = []
        prf_algos: List[str] = []
        auth_methods: List[str] = []

        # Parse SA payload if present (Next payload == 33 for IKEv2 SA, 1 for IKEv1 SA)
        try:
            if ike_ver == 2 and header["next_payload"] == 33:
                transforms = cls.parse_v2_transforms(payload_data)
                ciphers = transforms["encr"]
                dh_groups = transforms["dh"]
                integ_algos = transforms["integ"]
                prf_algos = transforms["prf"]
            elif ike_ver == 1 and header["next_payload"] == 1:
                transforms = cls.parse_v1_transforms(payload_data)
                ciphers = transforms["encr"]
                dh_groups = transforms["dh"]
                integ_algos = transforms["integ"]
                auth_methods = transforms["auth"]
        except Exception as e:
            logger.debug(f"Payload detail parsing skipped due to non-fatal parse error: {e}")

        return ParsedIKEExchange(
            ike_version=ike_ver,
            exchange_type_code=header["exchange_type"],
            exchange_type_name=header["exchange_name"],
            initiator_spi=header["initiator_spi"],
            responder_spi=header["responder_spi"],
            msg_id=header["msg_id"],
            is_response=header["is_response"],
            is_initiator=header["is_initiator"],
            next_payload=header["next_payload"],
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ciphers=ciphers,
            dh_groups=dh_groups,
            integrity_algos=integ_algos,
            prf_algos=prf_algos,
            auth_methods=auth_methods,
            raw_payload_length=header["length"],
        )

    @classmethod
    def parse_pcap(cls, file_source: Union[str, bytes]) -> List[ParsedVPNSessionData]:
        """Parse a full PCAP/PCAPNG file or raw PCAP bytes into aggregated VPN sessions."""
        sessions: Dict[str, ParsedVPNSessionData] = {}

        # 1. Primary parser attempt via Scapy
        try:
            if isinstance(file_source, bytes):
                packets = rdpcap(io.BytesIO(file_source))
            else:
                packets = rdpcap(file_source)

            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    proto = pkt[IP].proto

                    # ESP Packet (Protocol 50)
                    if proto == 50:
                        raw_load = bytes(pkt[IP].payload)
                        esp_spi = raw_load[:4].hex() if len(raw_load) >= 4 else "00000000"
                        key = f"esp_{min(src_ip, dst_ip)}_{max(src_ip, dst_ip)}"
                        if key not in sessions:
                            sessions[key] = ParsedVPNSessionData(
                                session_key=key,
                                ike_version=2,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=0,
                                dst_port=0,
                                initiator_spi="",
                                responder_spi="",
                                esp_spi=esp_spi,
                                esp_packets=1,
                                packet_count=1,
                            )
                        else:
                            sessions[key].esp_packets += 1
                            sessions[key].packet_count += 1
                        continue

                    # UDP Packet (Ports 500 / 4500)
                    if UDP in pkt:
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        if sport in (500, 4500) or dport in (500, 4500):
                            raw_udp_load = bytes(pkt[UDP].payload)
                            parsed_ex = cls.parse_packet_bytes(raw_udp_load, src_ip, dst_ip, sport, dport)
                            if parsed_ex:
                                session_key = parsed_ex.initiator_spi or f"{src_ip}:{sport}-{dst_ip}:{dport}"
                                if session_key not in sessions:
                                    sessions[session_key] = ParsedVPNSessionData(
                                        session_key=session_key,
                                        ike_version=parsed_ex.ike_version,
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        src_port=sport,
                                        dst_port=dport,
                                        initiator_spi=parsed_ex.initiator_spi,
                                        responder_spi=parsed_ex.responder_spi,
                                    )

                                s = sessions[session_key]
                                s.packet_count += 1
                                if parsed_ex.exchange_type_name not in s.exchange_types:
                                    s.exchange_types.append(parsed_ex.exchange_type_name)
                                if parsed_ex.responder_spi and parsed_ex.responder_spi != "0000000000000000":
                                    s.responder_spi = parsed_ex.responder_spi
                                if parsed_ex.ciphers and not s.cipher:
                                    s.cipher = parsed_ex.ciphers[0]
                                if parsed_ex.dh_groups and not s.dh_group:
                                    s.dh_group_num = parsed_ex.dh_groups[0][0]
                                    s.dh_group = parsed_ex.dh_groups[0][1]
                                if parsed_ex.integrity_algos and not s.integrity_algo:
                                    s.integrity_algo = parsed_ex.integrity_algos[0]
                                if parsed_ex.prf_algos and not s.prf_algo:
                                    s.prf_algo = parsed_ex.prf_algos[0]
                                if parsed_ex.auth_methods and not s.auth_method:
                                    s.auth_method = parsed_ex.auth_methods[0]

            if sessions:
                return list(sessions.values())

        except Exception as e:
            logger.warning(f"Scapy parser attempt logged exception: {e}. Attempting DPKT fallback...")

        # 2. Secondary fallback parser via DPKT
        try:
            stream = io.BytesIO(file_source) if isinstance(file_source, bytes) else open(file_source, "rb")
            try:
                pcap_reader = dpkt.pcap.Reader(stream)
            except Exception:
                stream.seek(0)
                pcap_reader = dpkt.pcapng.Reader(stream)

            for _, buf in pcap_reader:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not isinstance(ip, dpkt.ip.IP):
                        continue
                    src_ip = f"{ip.src[0]}.{ip.src[1]}.{ip.src[2]}.{ip.src[3]}"
                    dst_ip = f"{ip.dst[0]}.{ip.dst[1]}.{ip.dst[2]}.{ip.dst[3]}"

                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        if udp.sport in (500, 4500) or udp.dport in (500, 4500):
                            parsed_ex = cls.parse_packet_bytes(udp.data, src_ip, dst_ip, udp.sport, udp.dport)
                            if parsed_ex:
                                session_key = parsed_ex.initiator_spi or f"{src_ip}-{dst_ip}"
                                if session_key not in sessions:
                                    sessions[session_key] = ParsedVPNSessionData(
                                        session_key=session_key,
                                        ike_version=parsed_ex.ike_version,
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        src_port=udp.sport,
                                        dst_port=udp.dport,
                                        initiator_spi=parsed_ex.initiator_spi,
                                        responder_spi=parsed_ex.responder_spi,
                                    )
                                s = sessions[session_key]
                                s.packet_count += 1
                                if parsed_ex.exchange_type_name not in s.exchange_types:
                                    s.exchange_types.append(parsed_ex.exchange_type_name)
                                if parsed_ex.ciphers and not s.cipher:
                                    s.cipher = parsed_ex.ciphers[0]
                                if parsed_ex.dh_groups and not s.dh_group:
                                    s.dh_group_num = parsed_ex.dh_groups[0][0]
                                    s.dh_group = parsed_ex.dh_groups[0][1]
                except Exception:
                    continue
        except Exception as e2:
            logger.error(f"DPKT parser also encountered error: {e2}")

        return list(sessions.values())
