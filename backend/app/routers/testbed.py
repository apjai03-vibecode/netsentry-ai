"""
Testbed Router for NetSentry.ai.

Endpoints for generating and downloading strongSwan and Cisco IOS-XE testbed configurations,
and generating synthetic testbed PCAP traffic for any of the 7 supported traffic profiles.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from app.auth import get_current_user
from app.models import User
from app.testbed.generator import (
    IPsecTestbedGenerator,
    SUPPORTED_TESTBED_DH_GROUPS,
    SUPPORTED_TESTBED_CIPHERS,
    TestbedConfigRecord,
)
from app.testbed.traffic_generator import (
    SyntheticTrafficGenerator,
    TRAFFIC_PROFILES,
)

router = APIRouter(prefix="/testbed", tags=["Testbed & Traffic Generation"])


class GenerateConfigRequest(BaseModel):
    name: str = "custom-testbed-tunnel"
    ike_version: int = 2
    cipher: str = "aes256gcm16"
    dh_group: int = 14
    hash_algo: str = "sha256"
    pfs: bool = True
    mode: str = "tunnel"
    ip_version: str = "ipv4"


class GenerateTrafficRequest(BaseModel):
    scenario: str = "IKEV2_ESTABLISHED"
    profile: str = "WEB_BROWSING"
    packet_count: int = 40
    anomalous: bool = False


@router.get("/matrix", summary="Get supported testbed matrix and cryptographic options")
async def get_testbed_matrix(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Returns the supported testbed configurations and DH groups.
    Accurately marks only DH groups 1, 2, 5, 14, 19, 20, 31 as supported in the testbed,
    with other groups documented as unsupported by the testbed.
    """
    generator = IPsecTestbedGenerator()
    matrix = generator.generate_matrix()
    return {
        "supported_dh_groups": SUPPORTED_TESTBED_DH_GROUPS,
        "supported_ciphers": SUPPORTED_TESTBED_CIPHERS,
        "supported_traffic_profiles": list(TRAFFIC_PROFILES.keys()),
        "total_matrix_configurations": len(matrix),
        "configurations": [c.dict() for c in matrix[:20]],  # Sample of 20 configs
        "notice": (
            "Testbed supports DH groups 1, 2, 5, 14, 19, 20, 31 across strongSwan and Cisco IOS-XE templates. "
            "The NetSentry analyzer independently recognizes broader DH group identifiers 1–32."
        ),
    }


@router.post("/generate", summary="Generate strongSwan and Cisco IOS-XE configuration templates")
async def generate_configuration(
    req: GenerateConfigRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Generate dual configuration templates (swanctl.conf and Cisco IOS-XE) for the specified parameters."""
    generator = IPsecTestbedGenerator()
    try:
        record = generator.generate_config(
            name=req.name,
            ike_version=req.ike_version,
            cipher=req.cipher,
            dh_group=req.dh_group,
            hash_algo=req.hash_algo,
            pfs=req.pfs,
            mode=req.mode,
            ip_version=req.ip_version,
        )
        return {
            "status": "success",
            "configuration": record.dict(),
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/generate-traffic", summary="Generate synthetic PCAP traffic for testing and validation")
async def generate_traffic_pcap(
    req: GenerateTrafficRequest,
    current_user: User = Depends(get_current_user),
):
    """Generate and return synthetic PCAP bytes for the specified scenario and application profile."""
    pcap_gen = SyntheticTrafficGenerator()
    try:
        pcap_bytes = pcap_gen.generate_pcap(
            scenario=req.scenario,
            profile=req.profile,
            packet_count=req.packet_count,
            anomalous=req.anomalous,
        )
        filename = f"testbed_{req.scenario.lower()}_{req.profile.lower()}.pcap"
        return Response(
            content=pcap_bytes,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Traffic generation failed: {e}",
        )
