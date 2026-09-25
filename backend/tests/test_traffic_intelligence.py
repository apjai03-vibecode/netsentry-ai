"""Unit and integration tests for 14 Flow Features and Encrypted Traffic Classifier."""
import pytest
import numpy as np

from app.ml.flow_features import FLOW_FEATURE_NAMES, FlowFeatureExtractor, extract_14_flow_features
from app.ml.traffic_classifier import VPNEncryptedTrafficClassifier, TrafficClassificationResult
from app.parsers.live_capture import LiveCaptureEngine


def test_14_flow_features_exact_count_and_order():
    """Verify exactly 14 features are defined and extracted in documented order."""
    assert len(FLOW_FEATURE_NAMES) == 14
    assert FLOW_FEATURE_NAMES[0] == "packet_count"
    assert FLOW_FEATURE_NAMES[3] == "mean_packet_size"
    assert FLOW_FEATURE_NAMES[9] == "duration_seconds"
    assert FLOW_FEATURE_NAMES[13] == "burst_factor"


def test_flow_feature_extractor_synthetic():
    """Verify flow feature extraction produces valid non-zero values."""
    extractor = FlowFeatureExtractor()
    packet_sizes = [128, 256, 512, 1024, 1420]
    packet_times = [0.0, 0.02, 0.05, 0.10, 0.15]

    res = extractor.extract(packet_sizes=packet_sizes, packet_times=packet_times)
    vec = res.to_vector()

    assert len(vec) == 14
    assert vec[0] == 5.0  # packet_count
    assert vec[3] == float(np.mean(packet_sizes))  # mean_packet_size
    assert vec[5] == 128.0  # min_packet_size
    assert pytest.approx(vec[9], 0.001) == 0.15  # duration_seconds



def test_encrypted_traffic_classifier_inference():
    """Verify traffic classifier classifies 14-dim flow vectors and provides confidence."""
    classifier = VPNEncryptedTrafficClassifier.get_instance()
    # VoIP-like signature: small, uniform packets (~180 bytes), low duration
    voip_vec = [30.0, 2700.0, 2700.0, 180.0, 4.0, 160.0, 200.0, 50.0, 9000.0, 0.6, 0.02, 0.0001, 1.0, 1.1]

    result = classifier.classify(voip_vec)
    assert isinstance(result, TrafficClassificationResult)
    assert result.predicted_class in [
        "Web", "VoIP", "Video", "Messaging-like", "Email-like", "ICMP", "Bulk/Data", "Unknown"
    ]
    assert 0.0 <= result.confidence <= 1.0
    assert len(result.probabilities) > 0
    assert len(result.top_behavioral_indicators) > 0


def test_live_stream_simulation_lifecycle():
    """Verify live capture engine starts and stops simulation cleanly."""
    engine = LiveCaptureEngine()
    engine.reset()

    # Start simulation
    res = engine.start_simulation(scenario="IKEV2_ESTABLISHED", packet_count=10, rate_pps=50.0)
    assert res["status"] == "STARTED"
    assert engine.is_active

    # Check status
    status = engine.get_status()
    assert status["is_active"]
    assert status["mode"] == "STREAM_SIMULATION"

    # Stop simulation
    stop_res = engine.stop()
    assert stop_res["status"] == "STOPPED"
    assert not engine.is_active
