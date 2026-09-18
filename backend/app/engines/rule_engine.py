"""YAML-driven Rule Engine for RFC 4301 / RFC 7296 / RFC 8247 compliance checks."""
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

logger = logging.getLogger(__name__)

DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "ike_rules.yaml"


class RuleEngine:
    """Evaluates VPN session cryptographic parameters against YAML-defined security rules."""

    def __init__(self, rules_path: Optional[Union[str, Path]] = None):
        self.rules_path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Safely load rule definitions from YAML file."""
        if self.rules_path.exists():
            try:
                with open(self.rules_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    self.rules = data.get("rules", []) if isinstance(data, dict) else []
                logger.info(f"Loaded {len(self.rules)} rules from {self.rules_path}")
            except Exception as e:
                logger.error(f"Failed to load rules from {self.rules_path}: {e}")
                self.rules = []
        else:
            logger.warning(f"Rules definition file not found at {self.rules_path}")
            self.rules = []

    @staticmethod
    def _extract_field(session_data: Any, key: str, default: Any = None) -> Any:
        """Extract attribute from dict, object, or SQLAlchemy model safely."""
        if isinstance(session_data, dict):
            return session_data.get(key, default)
        return getattr(session_data, key, default)

    def evaluate(self, session_data: Any) -> List[Dict[str, Any]]:
        """
        Evaluate cryptographic and protocol parameters against loaded rules.
        Returns a list of structured finding dictionaries.
        """
        findings: List[Dict[str, Any]] = []
        if not self.rules:
            self.load_rules()

        # Extract normalized attributes
        dh_group_num = self._extract_field(session_data, "dh_group_num")
        dh_group = str(self._extract_field(session_data, "dh_group", "") or "")
        cipher = str(self._extract_field(session_data, "cipher", "") or "")
        integrity_algo = str(self._extract_field(session_data, "integrity_algo", "") or "")
        prf_algo = str(self._extract_field(session_data, "prf_algo", "") or "")
        ike_version = self._extract_field(session_data, "ike_version")
        exchange_type = str(self._extract_field(session_data, "exchange_type", "") or "")
        exchange_types = self._extract_field(session_data, "exchange_types", []) or []
        if isinstance(exchange_types, str):
            exchange_types = [s.strip() for s in exchange_types.split(",")]
        pfs_enabled = self._extract_field(session_data, "pfs_enabled", False)

        for rule in self.rules:
            rule_id = rule.get("rule_id")
            cond = rule.get("condition", {})
            matched = False
            evidence: Dict[str, Any] = {}

            # 1. Custom check: IKEv1 Aggressive mode
            if cond.get("custom_check") == "check_ikev1_aggressive":
                is_ikev1 = (ike_version == 1)
                is_aggressive = any("aggressive" in str(et).lower() for et in [exchange_type] + exchange_types)
                if is_ikev1 and is_aggressive:
                    matched = True
                    evidence = {
                        "ike_version": ike_version,
                        "exchange_type": exchange_type,
                        "exchange_types": exchange_types,
                        "reason": "IKEv1 Aggressive Mode was detected in the handshake sequence."
                    }

            # 2. Check in_list (e.g. DH group numbers)
            elif cond.get("check_type") == "in_list":
                target_field = cond.get("target_field")
                allowed_vals = cond.get("values", [])
                val = dh_group_num if target_field == "dh_group_num" else self._extract_field(session_data, target_field)

                if val is not None:
                    if val in allowed_vals:
                        matched = True
                        evidence = {"field": target_field, "offending_value": val, "dh_group_name": dh_group}
                elif dh_group:
                    # Fallback string matching on group name only when numeric value is absent
                    import re
                    fallback_matches = cond.get("fallback_name_match", [])
                    for m in fallback_matches:
                        if re.search(rf"\b{re.escape(m)}\b", dh_group, re.IGNORECASE):
                            matched = True
                            evidence = {"field": "dh_group", "offending_value": dh_group}
                            break

            # 3. Check contains_any (e.g. Deprecated ciphers, weak hashes)
            elif cond.get("check_type") == "contains_any":
                target_fields = cond.get("target_fields") or [cond.get("target_field")]
                values_to_match = [v.upper() for v in cond.get("values", [])]

                for tf in target_fields:
                    raw_val = str(self._extract_field(session_data, tf, "") or "").upper()
                    if raw_val:
                        for bad_val in values_to_match:
                            # Match whole token or substring (e.g. '3DES' in '3DES-CBC', 'MD5' in 'HMAC-MD5')
                            if bad_val in raw_val:
                                matched = True
                                evidence = {"field": tf, "offending_value": raw_val, "matched_pattern": bad_val}
                                break
                    if matched:
                        break

            # 4. Check equals (e.g. missing PFS or legacy IKEv1)
            elif cond.get("check_type") == "equals":
                target_field = cond.get("target_field")
                expected_val = cond.get("value")
                actual_val = self._extract_field(session_data, target_field)

                if actual_val is not None and actual_val == expected_val:
                    # For PFS check, only trigger if session established IPsec or Child SA
                    if target_field == "pfs_enabled" and not actual_val:
                        matched = True
                        evidence = {"field": target_field, "offending_value": False, "reason": "PFS is disabled"}
                    elif target_field != "pfs_enabled":
                        matched = True
                        evidence = {"field": target_field, "offending_value": actual_val}

            if matched:
                findings.append({
                    "rule_id": rule_id,
                    "category": rule.get("category", "Cryptography"),
                    "severity": rule.get("severity", "MEDIUM"),
                    "title": rule.get("name", rule_id),
                    "description": rule.get("description", "").strip(),
                    "rfc_reference": rule.get("rfc", "RFC 7296"),
                    "evidence_json": json.dumps(evidence),
                    "remediation_hint": rule.get("remediation", "").strip(),
                })

        return findings
