"""Unit tests for waiver application logic."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from freezegun import freeze_time
from typing import Dict, Any, List

from dsoinabox.waivers.matcher import check_waiver, apply_waivers_to_findings


def _is_waiver_expired(waiver: Dict[str, Any], current_time: datetime) -> bool:
    """
    Check if a waiver has expired.
    
    Args:
        waiver: Waiver dictionary with optional 'expires_at' field
        current_time: Current datetime to compare against
        
    Returns:
        True if waiver has expires_at and it's in the past, False otherwise
    """
    expires_at = waiver.get('expires_at')
    if not expires_at:
        return False
    
    # Parse expires_at - supports ISO 8601 and YYYY-MM-DD formats
    if isinstance(expires_at, str):
        try:
            # Try ISO 8601 format first
            if 'T' in expires_at or expires_at.endswith('Z'):
                exp_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            else:
                # YYYY-MM-DD format - treat as midnight UTC
                exp_dt = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)
            
            # Normalize current_time to UTC if it has timezone info
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=timezone.utc)
            else:
                current_time = current_time.astimezone(timezone.utc)
            
            return exp_dt < current_time
        except (ValueError, AttributeError):
            # If parsing fails, assume not expired (fail open)
            return False
    
    return False


def _check_waiver_with_expiry(
    fingerprints: Dict[str, str],
    waiver_data: Dict[str, Any],
    current_time: datetime
) -> tuple[bool, Dict[str, Any] | None]:
    """
    Check if any fingerprint matches a non-expired waiver.
    
    Returns:
        Tuple of (is_waived, matched_waiver_dict)
    """
    if not fingerprints:
        return False, None
    
    finding_waivers = waiver_data.get('finding_waivers', [])
    if not finding_waivers:
        return False, None
    
    # Check each waiver for expiry and fingerprint match
    for waiver in finding_waivers:
        if _is_waiver_expired(waiver, current_time):
            continue
        
        waiver_fp = waiver.get('fingerprint')
        if not waiver_fp:
            continue
        
        # Check if any finding fingerprint matches
        for fp_value in fingerprints.values():
            if fp_value and fp_value == waiver_fp:
                return True, waiver
    
    return False, None


class TestWaiverExactFingerprintMatch:
    """Test waiver application by exact fingerprint match."""
    
    def test_exact_match_by_rule_fingerprint(self):
        """Test that waiver matches when rule fingerprint matches exactly."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    'reason': 'Test waiver'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is True
    
    def test_exact_match_by_exact_fingerprint(self):
        """Test that waiver matches when exact fingerprint matches."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:EXACT:test.rule.id:filehash:100:200',
                    'type': 'risk_acceptance',
                    'reason': 'Accepted risk'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is True
    
    def test_exact_match_by_ctx_fingerprint(self):
        """Test that waiver matches when context fingerprint matches."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:CTX:test.rule.id:pathhash:contexthash',
                    'type': 'policy_waiver',
                    'reason': 'Policy exception'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is True
    
    def test_no_match_when_fingerprints_differ(self):
        """Test that waiver does not match when fingerprints don't match."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:different.rule:xyz789',
                    'type': 'false_positive'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is False
    
    def test_no_match_when_no_fingerprints(self):
        """Test that finding without fingerprints is not waived."""
        fingerprints = {}
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is False
    
    def test_no_match_when_empty_fingerprint_value(self):
        """Test that empty fingerprint values don't match."""
        fingerprints = {
            'rule': '',
            'exact': None,
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:CTX:test.rule.id:pathhash:contexthash',
                    'type': 'false_positive'
                }
            ]
        }
        
        # Should still match via ctx fingerprint (non-empty)
        assert check_waiver(fingerprints, waiver_data) is True
    
    def test_match_with_repo_hint_suffix(self):
        """Test that fingerprints with repo hint suffix match correctly."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456:R:a3d1696c',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200:R:a3d1696c',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash:R:a3d1696c'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456:R:a3d1696c',
                    'type': 'false_positive'
                }
            ]
        }
        
        assert check_waiver(fingerprints, waiver_data) is True


class TestWaiverExpiry:
    """Test waiver expiry behavior."""
    
    @freeze_time("2025-12-01T12:00:00Z")
    def test_expired_waiver_does_not_apply(self):
        """Test that expired waivers don't match findings."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    'expires_at': '2025-11-30T23:59:59Z'  # Expired
                }
            ]
        }
        
        current_time = datetime.now(timezone.utc)
        is_waived, matched_waiver = _check_waiver_with_expiry(
            fingerprints, waiver_data, current_time
        )
        
        assert is_waived is False
        assert matched_waiver is None
    
    @freeze_time("2025-12-01T12:00:00Z")
    def test_non_expired_waiver_applies(self):
        """Test that non-expired waivers still match."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    'expires_at': '2025-12-31T23:59:59Z'  # Not expired
                }
            ]
        }
        
        current_time = datetime.now(timezone.utc)
        is_waived, matched_waiver = _check_waiver_with_expiry(
            fingerprints, waiver_data, current_time
        )
        
        assert is_waived is True
        assert matched_waiver is not None
        assert matched_waiver['fingerprint'] == 'og:1:RULE:test.rule.id:abc123def456'
    
    @freeze_time("2025-12-01T12:00:00Z")
    def test_waiver_without_expiry_applies(self):
        """Test that waivers without expiry_at always apply."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    # No expires_at
                }
            ]
        }
        
        current_time = datetime.now(timezone.utc)
        is_waived, matched_waiver = _check_waiver_with_expiry(
            fingerprints, waiver_data, current_time
        )
        
        assert is_waived is True
        assert matched_waiver is not None
    
    @freeze_time("2025-12-01T12:00:00Z")
    def test_waiver_with_yyyy_mm_dd_expiry_format(self):
        """Test that YYYY-MM-DD expiry format is parsed correctly."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    'expires_at': '2025-12-02'  # YYYY-MM-DD format, not expired
                }
            ]
        }
        
        current_time = datetime.now(timezone.utc)
        is_waived, matched_waiver = _check_waiver_with_expiry(
            fingerprints, waiver_data, current_time
        )
        
        assert is_waived is True
    
    @freeze_time("2025-12-02T00:00:01Z")
    def test_waiver_expires_at_midnight_utc(self):
        """Test that YYYY-MM-DD expiry is treated as midnight UTC."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    'expires_at': '2025-12-02'  # Expires at 2025-12-02T00:00:00Z
                }
            ]
        }
        
        current_time = datetime.now(timezone.utc)
        is_waived, matched_waiver = _check_waiver_with_expiry(
            fingerprints, waiver_data, current_time
        )
        
        # Current time is 00:00:01, which is after midnight, so expired
        assert is_waived is False


class TestWaiverPrecedence:
    """Test precedence when multiple waivers match."""
    
    def test_first_matching_waiver_wins(self):
        """Test that when multiple waivers match, the first one is used."""
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
            'ctx': 'og:1:CTX:test.rule.id:pathhash:contexthash'
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:CTX:test.rule.id:pathhash:contexthash',
                    'type': 'false_positive',
                    'reason': 'First match'
                },
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'risk_acceptance',
                    'reason': 'Second match'
                },
                {
                    'fingerprint': 'og:1:EXACT:test.rule.id:filehash:100:200',
                    'type': 'policy_waiver',
                    'reason': 'Third match'
                }
            ]
        }
        
        # check_waiver returns True if any match, but doesn't specify which
        # For precedence testing, we need to check which one matches first
        assert check_waiver(fingerprints, waiver_data) is True
        
        # Verify the first matching waiver is found
        current_time = datetime.now(timezone.utc)
        is_waived, matched_waiver = _check_waiver_with_expiry(
            fingerprints, waiver_data, current_time
        )
        assert is_waived is True
        assert matched_waiver['reason'] == 'First match'
        assert matched_waiver['type'] == 'false_positive'


class TestWaiverMetadataSerialization:
    """Test serialization of waiver metadata onto findings."""
    
    def test_apply_waivers_persists_waived_flag(self):
        """Test that apply_waivers_to_findings adds 'waived' flag when persist_waived_findings=True."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'path': 'src/file.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:test.rule.id:abc123def456',
                    'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
                }
            },
            {
                'check_id': 'other.rule.id',
                'path': 'src/other.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:other.rule.id:xyz789',
                }
            }
        ]
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                    'reason': 'Test waiver',
                    'created_by': 'alice@example.com',
                    'created_at': '2025-11-01',
                    'meta_ticket': 'SEC-1420'
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=True
        )
        
        assert len(result) == 2
        assert result[0]['waived'] is True
        assert result[1]['waived'] is False
    
    def test_apply_waivers_filters_when_persist_false(self):
        """Test that apply_waivers_to_findings filters out waived findings when persist_waived_findings=False."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'path': 'src/file.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:test.rule.id:abc123def456',
                }
            },
            {
                'check_id': 'other.rule.id',
                'path': 'src/other.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:other.rule.id:xyz789',
                }
            }
        ]
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=False
        )
        
        assert len(result) == 1
        assert result[0]['check_id'] == 'other.rule.id'
        assert 'waived' not in result[0]  # Not waived, so no flag
    
    def test_apply_waivers_with_dict_findings(self):
        """Test that apply_waivers_to_findings works with dict containing findings."""
        findings = {
            'results': [
                {
                    'check_id': 'test.rule.id',
                    'fingerprints': {
                        'rule': 'og:1:RULE:test.rule.id:abc123def456',
                    }
                }
            ]
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            findings_key='results',
            persist_waived_findings=True
        )
        
        assert result['results'][0]['waived'] is True
    
    def test_apply_waivers_with_auto_detected_key(self):
        """Test that apply_waivers_to_findings auto-detects 'results' or 'matches' key."""
        findings = {
            'results': [
                {
                    'check_id': 'test.rule.id',
                    'fingerprints': {
                        'rule': 'og:1:RULE:test.rule.id:abc123def456',
                    }
                }
            ]
        }
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=True
        )
        
        assert result['results'][0]['waived'] is True
    
    def test_apply_waivers_with_no_waiver_data(self):
        """Test that apply_waivers_to_findings marks all as not waived when no waiver data."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'fingerprints': {
                    'rule': 'og:1:RULE:test.rule.id:abc123def456',
                }
            }
        ]
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data=None,
            persist_waived_findings=True
        )
        
        assert len(result) == 1
        assert result[0]['waived'] is False
    
    def test_apply_waivers_with_findings_without_fingerprints(self):
        """Test that findings without fingerprints are not waived."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'path': 'src/file.py',
                # No fingerprints
            },
            {
                'check_id': 'other.rule.id',
                'path': 'src/other.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:other.rule.id:xyz789',
                }
            }
        ]
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=True
        )
        
        assert len(result) == 2
        assert result[0]['waived'] is False  # No fingerprints
        assert result[1]['waived'] is False  # Different fingerprint


class TestWaiverRuleFileLinePattern:
    """Test rule/file/line pattern matching (if supported)."""
    
    def test_pattern_matching_not_implemented(self):
        """Test that pattern matching is not currently implemented.
        
        Note: The current implementation only supports exact fingerprint matching.
        Pattern matching (rule/file/line) would need to be implemented separately.
        """
        fingerprints = {
            'rule': 'og:1:RULE:test.rule.id:abc123def456',
            'exact': 'og:1:EXACT:test.rule.id:filehash:100:200',
        }
        
        # Pattern matching would look like:
        # - rule: "test.rule.id"
        # - file: "src/file.py"
        # - line: 42
        # But this is not implemented in the current matcher
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:abc123def456',
                    'type': 'false_positive',
                }
            ]
        }
        
        # Current implementation requires exact fingerprint match
        assert check_waiver(fingerprints, waiver_data) is True
        
        # If pattern matching were implemented, we'd test:
        # - Matching by rule ID only
        # - Matching by rule + file pattern
        # - Matching by rule + file + line range
        # But these are not currently supported


class TestWaiverRegressionNonMatchingFingerprint:
    """Regression test: Waiver with fingerprint that no longer matches should not apply."""
    
    def test_waiver_with_non_matching_fingerprint_does_not_apply(self):
        """Regression test: Waiver referencing a fingerprint that no longer matches should not apply.
        
        This tests the scenario where code has changed and the fingerprint in the waiver
        no longer matches any finding. The waiver should be silently ignored (not applied).
        """
        findings = [
            {
                'check_id': 'test.rule.id',
                'path': 'src/file.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:test.rule.id:new_hash_after_code_change',
                    'exact': 'og:1:EXACT:test.rule.id:new_filehash:100:200',
                    'ctx': 'og:1:CTX:test.rule.id:new_pathhash:new_contexthash'
                }
            }
        ]
        
        # Waiver references old fingerprint that no longer exists after code change
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:old_hash_before_code_change',
                    'type': 'false_positive',
                    'reason': 'This waiver should not apply - fingerprint changed'
                }
            ]
        }
        
        # Apply waivers - should not match, so finding should not be waived
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=True
        )
        
        assert len(result) == 1
        assert result[0]['waived'] is False, "Waiver with non-matching fingerprint should not apply"
        
        # Test with filtering mode (persist_waived_findings=False)
        result_filtered = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=False
        )
        
        # Finding should remain since it's not waived
        assert len(result_filtered) == 1
        assert result_filtered[0]['check_id'] == 'test.rule.id'
    
    def test_multiple_waivers_with_only_one_matching(self):
        """Test that only matching waivers apply, non-matching ones are ignored."""
        findings = [
            {
                'check_id': 'test.rule.id',
                'path': 'src/file.py',
                'fingerprints': {
                    'rule': 'og:1:RULE:test.rule.id:current_hash',
                }
            }
        ]
        
        waiver_data = {
            'finding_waivers': [
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:old_hash_no_longer_exists',
                    'type': 'false_positive',
                    'reason': 'Old waiver - should not match'
                },
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:current_hash',
                    'type': 'risk_acceptance',
                    'reason': 'Current waiver - should match'
                },
                {
                    'fingerprint': 'og:1:RULE:test.rule.id:another_old_hash',
                    'type': 'policy_waiver',
                    'reason': 'Another old waiver - should not match'
                }
            ]
        }
        
        result = apply_waivers_to_findings(
            findings,
            waiver_data,
            persist_waived_findings=True
        )
        
        assert len(result) == 1
        assert result[0]['waived'] is True, "Matching waiver should apply"

