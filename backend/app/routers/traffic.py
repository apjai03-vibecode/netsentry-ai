"""
Traffic Intelligence Router for NetSentry.ai.

Endpoints for:
1. 14 Flow Features documentation & feature extraction
2. Supervised Encrypted Traffic Classifier inference
3. Live stream capture and non-blocking simulation controls
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth import get_current_user
from app.models import User
from app.ml.flow_features import FLOW_FEATURE_NAMES, FlowFeatureExtractor
from app.ml.traffic_classifier import VPNEncryptedTrafficClassifier, ClassificationResult
from app.parsers.live_capture import LiveCaptureEngine

router = APIRouter(prefix="/traffic", tags=["Encrypted Traffic Intelligence"])


class ClassifyFlowRequest(BaseModel):
    feature_vector: Optional[List[float]] = None
    packet_sizes: Optional[List[int]] = None
    packet_times: Optional[List[float]] = None
    flow_duration: Optional[float] = None
    flow_bytes: Optional[int] = None
    packet_count: Optional[int] = None


class StartSimulationRequest(BaseModel):
    scenario: str = "IKEV2_ESTABLISHED"
    packet_count: int = 50
    rate_pps: float = 5.0


@router.get("/features", summary="List the exactly 14 extracted flow features")
async def get_flow_features(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Returns the exact catalog of 14 flow features used by the encrypted traffic classifier,
    including mathematical definitions, units, and security relevance.
    """
    definitions = [
        {"name": "flow_duration_ms", "type": "float", "unit": "ms", "description": "Total duration of the IPsec/ESP session flow in milliseconds."},
        {"name": "total_packets", "type": "int", "unit": "count", "description": "Total count of observed packets in the session flow."},
        {"name": "total_bytes", "type": "int", "unit": "bytes", "description": "Total volume of bytes transmitted across the flow."},
        {"name": "mean_packet_size", "type": "float", "unit": "bytes", "description": "Arithmetic mean of all outer IP packet lengths."},
        {"name": "std_packet_size", "type": "float", "unit": "bytes", "description": "Standard deviation of packet lengths; distinguishes uniform audio frames from variable web payloads."},
        {"name": "min_packet_size", "type": "float", "unit": "bytes", "description": "Minimum observed packet length in the flow."},
        {"name": "max_packet_size", "type": "float", "unit": "bytes", "description": "Maximum observed packet length; detects MTU-capped bulk transfers."},
        {"name": "mean_iat_ms", "type": "float", "unit": "ms", "description": "Mean inter-arrival time between successive packets in milliseconds."},
        {"name": "std_iat_ms", "type": "float", "unit": "ms", "description": "Standard deviation of inter-arrival times; distinguishes constant bit-rate traffic from interactive bursts."},
        {"name": "min_iat_ms", "type": "float", "unit": "ms", "description": "Minimum observed inter-arrival time between packets."},
        {"name": "max_iat_ms", "type": "float", "unit": "ms", "description": "Maximum observed inter-arrival time in the flow."},
        {"name": "bytes_per_second", "type": "float", "unit": "B/s", "description": "Throughput rate in bytes per second."},
        {"name": "packets_per_second", "type": "float", "unit": "pkts/s", "description": "Packet generation rate in packets per second."},
        {"name": "payload_entropy_approx", "type": "float", "unit": "entropy", "description": "Approximate Shannon entropy metric; flags deviation from standard encrypted ESP distributions."},
    ]
    return {
        "feature_count": len(FLOW_FEATURE_NAMES),
        "feature_names": FLOW_FEATURE_NAMES,
        "features": definitions,
    }


@router.post("/classify", summary="Classify encrypted traffic flow from 14 features or packet series")
async def classify_traffic(
    req: ClassifyFlowRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Run supervised encrypted traffic classifier on 14 flow features or raw packet statistics."""
    classifier = VPNEncryptedTrafficClassifier.get_instance()

    features = req.feature_vector
    if not features:
        # Extract 14 features from raw packet sizes/times
        packet_sizes = req.packet_sizes or [128, 512, 1024, 64]
        packet_times = req.packet_times or [0.0, 0.02, 0.05, 0.10]
        extractor = FlowFeatureExtractor()
        extracted = extractor.extract(
            packet_sizes=packet_sizes,
            packet_times=packet_times,
            flow_duration=req.flow_duration,
            flow_bytes=req.flow_bytes,
            packet_count=req.packet_count,
        )
        features = extracted.to_vector()

    result = classifier.classify(features)
    return {
        "status": "success",
        "result": result.dict(),
    }


@router.get("/live/status", summary="Get status of live capture or stream simulation")
async def get_live_status(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Returns current live capture or stream simulator state, recent packets, and FSM summary."""
    engine = LiveCaptureEngine()
    return engine.get_status()


@router.post("/live/start", summary="Start live stream simulation")
async def start_live_simulation(
    req: StartSimulationRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Starts a non-blocking stream simulation at controlled packet rates into the FSM pipeline."""
    engine = LiveCaptureEngine()
    return engine.start_simulation(
        scenario=req.scenario,
        packet_count=req.packet_count,
        rate_pps=req.rate_pps,
    )


@router.post("/live/stop", summary="Stop live capture or stream simulation")
async def stop_live_capture(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Stops any active sniffer or streaming simulation."""
    engine = LiveCaptureEngine()
    return engine.stop()
