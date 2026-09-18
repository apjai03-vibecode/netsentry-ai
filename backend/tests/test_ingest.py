"""Tests for Crypto, IKE/IPsec Parser, and Ingestion Router."""
import io
import struct
import pytest
from httpx import AsyncClient
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapWriter

from app.core.crypto import (
    CryptographicError,
    decrypt_bytes,
    decrypt_file_to_bytes,
    encrypt_bytes,
    encrypt_file,
)
from app.parsers.ike_parser import IKEParser


# ---------------------------------------------------------------------------
# Helper: Build a realistic synthetic IKEv2 packet with SA Proposals
# ---------------------------------------------------------------------------
def build_synthetic_ikev2_init_packet(
    initiator_spi: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88",
    responder_spi: bytes = b"\x00" * 8,
    dh_group_id: int = 14,
    encr_id: int = 12,  # AES-CBC
    key_len: int = 256,
) -> bytes:
    """Constructs a valid IKEv2 IKE_SA_INIT packet payload with transforms."""
    # Build Transforms:
    # 1. ENCR: AES-CBC (12) + key len 256
    # Transform header: last(1), reserved(1), trans_len(2), trans_type(1), reserved(1), trans_id(2)
    # Attribute: type 14 (Key Length), value 256
    attr_key_len = struct.pack("!HH", 0x8000 | 14, key_len)
    t1 = struct.pack("!BBHBBH", 3, 0, 8 + len(attr_key_len), 1, 0, encr_id) + attr_key_len

    # 2. PRF: PRF_HMAC_SHA2_256 (5)
    t2 = struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 5)

    # 3. INTEG: AUTH_HMAC_SHA2_256_128 (12)
    t3 = struct.pack("!BBHBBH", 3, 0, 8, 3, 0, 12)

    # 4. DH: Group 14 (or custom)
    t4 = struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_group_id)

    transforms_payload = t1 + t2 + t3 + t4
    num_transforms = 4

    # Proposal header:
    # last(1), reserved(1), prop_len(2), prop_num(1), proto_id(1)=IKE(1), spi_size(1)=0, num_transforms(1)
    prop_len = 8 + len(transforms_payload)
    proposal = struct.pack("!BBHBBBB", 0, 0, prop_len, 1, 1, 0, num_transforms) + transforms_payload

    # SA Payload Header: next_payload(1)=0, critical(1)=0, sa_len(2)
    sa_len = 4 + len(proposal)
    sa_payload = struct.pack("!BBH", 0, 0, sa_len) + proposal

    # IKEv2 Header:
    # init_spi(8), resp_spi(8), next_payload(1)=33(SA), ver(1)=0x20, exch_type(1)=34, flags(1)=0x08, msg_id(4)=0, len(4)
    total_len = 28 + len(sa_payload)
    ike_header = struct.pack(
        "!8s8sBBBBII",
        initiator_spi,
        responder_spi,
        33,    # Next Payload: SA (33)
        0x20,  # Version: 2.0
        34,    # Exchange: IKE_SA_INIT (34)
        0x08,  # Flags: Initiator
        0,     # Message ID
        total_len,
    )
    return ike_header + sa_payload


def build_synthetic_pcap_bytes(ike_payload: bytes, src_ip="192.168.1.100", dst_ip="198.51.100.1") -> bytes:
    """Wrap IKE payload in IP/UDP and write to in-memory PCAP."""
    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / ike_payload
    buf = io.BytesIO()
    writer = PcapWriter(buf, sync=True)
    writer.write(pkt)
    writer.flush()
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Cryptographic Tests
# ---------------------------------------------------------------------------
def test_crypto_roundtrip():
    """Verify encryption and decryption restores exact plaintext bytes."""
    secret_data = b"NetSentry-Secret-Capture-Data-RFC7296"
    encrypted = encrypt_bytes(secret_data)
    assert encrypted != secret_data

    decrypted = decrypt_bytes(encrypted)
    assert decrypted == secret_data


def test_crypto_corrupted_ciphertext():
    """Verify decryption fails gracefully when ciphertext is corrupted."""
    with pytest.raises(CryptographicError):
        decrypt_bytes(b"invalid_corrupted_token_data")


def test_crypto_file_operations(tmp_path):
    """Verify encrypt_file and decrypt_file_to_bytes file workflow."""
    sample_file = tmp_path / "plain.bin"
    enc_file = tmp_path / "plain.enc"
    sample_data = b"Simulated packet capture stream in temporary storage"
    sample_file.write_bytes(sample_data)

    encrypt_file(sample_file, enc_file)
    assert enc_file.exists()
    assert enc_file.read_bytes() != sample_data

    decrypted_content = decrypt_file_to_bytes(enc_file)
    assert decrypted_content == sample_data


# ---------------------------------------------------------------------------
# Parser Unit Tests
# ---------------------------------------------------------------------------
def test_ike_packet_parser():
    """Verify deep transform extraction from raw IKEv2 payload."""
    raw_packet = build_synthetic_ikev2_init_packet(
        initiator_spi=b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11",
        dh_group_id=14,
        encr_id=12,
        key_len=256,
    )
    parsed = IKEParser.parse_packet_bytes(
        raw_packet,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=500,
        dst_port=500,
    )
    assert parsed is not None
    assert parsed.ike_version == 2
    assert parsed.exchange_type_name == "IKE_SA_INIT"
    assert parsed.initiator_spi == "aabbccddeeff0011"
    assert parsed.responder_spi == "0000000000000000"
    assert "AES-CBC-256" in parsed.ciphers
    assert any(g[0] == 14 for g in parsed.dh_groups)
    assert "AUTH_HMAC_SHA2_256_128" in parsed.integrity_algos
    assert "PRF_HMAC_SHA2_256" in parsed.prf_algos


def test_pcap_full_stream_parser():
    """Verify full PCAP file parsing extracts aggregated sessions."""
    raw_packet = build_synthetic_ikev2_init_packet(
        initiator_spi=b"\x12\x34\x56\x78\x9a\xbc\xde\xf0",
        dh_group_id=14,
        encr_id=12,
        key_len=128,
    )
    pcap_bytes = build_synthetic_pcap_bytes(raw_packet)
    sessions = IKEParser.parse_pcap(pcap_bytes)

    assert len(sessions) == 1
    sess = sessions[0]
    assert sess.ike_version == 2
    assert sess.initiator_spi == "123456789abcdef0"
    assert sess.cipher == "AES-CBC-128"
    assert sess.dh_group_num == 14
    assert "IKE_SA_INIT" in sess.exchange_types


# ---------------------------------------------------------------------------
# Ingestion API Integration Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_upload_valid_pcap(client: AsyncClient):
    """Test authenticated PCAP upload endpoint."""
    # 1. Register and login
    await client.post("/api/auth/register", json={
        "username": "ingest_analyst",
        "email": "ingest@netsentry.internal",
        "password": "Password123!",
        "role": "analyst",
    })
    login_res = await client.post("/api/auth/login/json", json={
        "username": "ingest_analyst",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Build valid PCAP
    raw_packet = build_synthetic_ikev2_init_packet()
    pcap_content = build_synthetic_pcap_bytes(raw_packet)

    # 3. Upload file
    files = {"file": ("vpn_traffic.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
    response = await client.post("/api/ingest/upload", headers=headers, files=files)

    assert response.status_code == 202
    job_data = response.json()
    assert job_data["filename"] == "vpn_traffic.pcap"
    assert job_data["file_type"] == "pcap"
    assert job_data["status"] in ("queued", "completed")
    job_id = job_data["id"]

    # 4. Check job status
    status_res = await client.get(f"/api/ingest/jobs/{job_id}", headers=headers)
    assert status_res.status_code == 200
    assert status_res.json()["id"] == job_id


@pytest.mark.asyncio
async def test_upload_invalid_file_rejected(client: AsyncClient):
    """Verify upload fails with 400 if magic bytes don't match PCAP/PCAPNG/config."""
    # Register & login
    await client.post("/api/auth/register", json={
        "username": "bad_uploader",
        "email": "bad_uploader@netsentry.internal",
        "password": "Password123!",
        "role": "analyst",
    })
    login_res = await client.post("/api/auth/login/json", json={
        "username": "bad_uploader",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Random binary that doesn't have PCAP magic bytes
    bad_binary = b"MZ\x90\x00\x03\x00\x00\x00ThisIsNotAPCAP"
    files = {"file": ("malicious.exe", bad_binary, "application/octet-stream")}
    response = await client.post("/api/ingest/upload", headers=headers, files=files)

    assert response.status_code == 400
    assert "Invalid file format" in response.json()["detail"]


@pytest.mark.asyncio
async def test_upload_unauthorized_fails(client: AsyncClient):
    """Verify upload is blocked without valid Bearer token."""
    raw_packet = build_synthetic_ikev2_init_packet()
    pcap_content = build_synthetic_pcap_bytes(raw_packet)
    files = {"file": ("vpn.pcap", pcap_content, "application/vnd.tcpdump.pcap")}

    response = await client.post("/api/ingest/upload", files=files)
    assert response.status_code == 401
