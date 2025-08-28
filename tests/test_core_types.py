#!/usr/bin/env python3
"""
Unit Tests for Core Types and Data Structures

Tests the core data structures, enums, and validation logic used
throughout the security guard system.
"""

import pytest
from dataclasses import FrozenInstanceError

from src.core_types import (
    SecurityDecision, ThreatPattern, PatternMatch, ReasoningStep,
    SecurityResult, SecurityContext
)


class TestSecurityDecision:
    """Test SecurityDecision enum"""
    
    def test_enum_values(self):
        """Test that enum has expected values"""
        assert SecurityDecision.ALLOW.value == "ALLOW"
        assert SecurityDecision.REVIEW.value == "REVIEW"
        assert SecurityDecision.SANITIZE.value == "SANITIZE"
        assert SecurityDecision.BLOCK.value == "BLOCK"
    
    def test_enum_comparison(self):
        """Test enum comparison"""
        assert SecurityDecision.ALLOW == SecurityDecision.ALLOW
        assert SecurityDecision.BLOCK != SecurityDecision.ALLOW


class TestThreatPattern:
    """Test ThreatPattern dataclass"""
    
    def test_valid_pattern_creation(self):
        """Test creating valid threat patterns"""
        pattern = ThreatPattern(
            name="test_pattern",
            pattern=r"dangerous.*content",
            severity="BLOCK",
            category="test",
            weight=0.8,
            description="Test pattern"
        )
        
        assert pattern.name == "test_pattern"
        assert pattern.weight == 0.8
        assert pattern.severity == "BLOCK"
    
    def test_invalid_weight_validation(self):
        """Test weight validation"""
        with pytest.raises(ValueError, match="Pattern weight must be 0.0-1.0"):
            ThreatPattern(
                name="invalid",
                pattern="test",
                severity="BLOCK",
                category="test",
                weight=2.0  # Invalid weight
            )
        
        with pytest.raises(ValueError, match="Pattern weight must be 0.0-1.0"):
            ThreatPattern(
                name="invalid",
                pattern="test", 
                severity="BLOCK",
                category="test",
                weight=-0.5  # Invalid weight
            )
    
    def test_invalid_severity_validation(self):
        """Test severity validation"""
        with pytest.raises(ValueError, match="Invalid severity"):
            ThreatPattern(
                name="invalid",
                pattern="test",
                severity="INVALID",  # Invalid severity
                category="test"
            )
    
    def test_default_values(self):
        """Test default values"""
        pattern = ThreatPattern(
            name="minimal",
            pattern="test",
            severity="ALLOW",
            category="test"
        )
        
        assert pattern.weight == 1.0
        assert pattern.description == ""


class TestPatternMatch:
    """Test PatternMatch dataclass"""
    
    def test_pattern_match_creation(self):
        """Test creating pattern matches"""
        pattern = ThreatPattern(
            name="test", pattern="test", severity="BLOCK", category="test"
        )
        
        match = PatternMatch(
            pattern=pattern,
            match_text="dangerous content",
            start_pos=10,
            end_pos=27,
            confidence=0.9,
            context="This is dangerous content here"
        )
        
        assert match.pattern.name == "test"
        assert match.match_text == "dangerous content"
        assert match.start_pos == 10
        assert match.end_pos == 27
        assert match.confidence == 0.9


class TestReasoningStep:
    """Test ReasoningStep dataclass"""
    
    def test_reasoning_step_creation(self):
        """Test creating reasoning steps"""
        step = ReasoningStep(
            rule_name="test_rule",
            premises=["premise1", "premise2"],
            conclusion="test conclusion",
            confidence=0.8,
            metadata={"extra": "info"}
        )
        
        assert step.rule_name == "test_rule"
        assert len(step.premises) == 2
        assert step.conclusion == "test conclusion"
        assert step.confidence == 0.8
        assert step.metadata["extra"] == "info"


class TestSecurityResult:
    """Test SecurityResult dataclass"""
    
    def test_valid_result_creation(self):
        """Test creating valid security results"""
        result = SecurityResult(
            decision=SecurityDecision.BLOCK,
            confidence=0.9,
            threat_score=0.8,
            matched_patterns=[],
            reasoning_chain=[]
        )
        
        assert result.decision == SecurityDecision.BLOCK
        assert result.confidence == 0.9
        assert result.threat_score == 0.8
    
    def test_confidence_validation(self):
        """Test confidence value validation"""
        with pytest.raises(ValueError, match="Confidence must be 0.0-1.0"):
            SecurityResult(
                decision=SecurityDecision.ALLOW,
                confidence=1.5,  # Invalid
                threat_score=0.5,
                matched_patterns=[],
                reasoning_chain=[]
            )
    
    def test_threat_score_validation(self):
        """Test threat score validation"""
        with pytest.raises(ValueError, match="Threat score must be 0.0-1.0"):
            SecurityResult(
                decision=SecurityDecision.ALLOW,
                confidence=0.9,
                threat_score=-0.1,  # Invalid
                matched_patterns=[],
                reasoning_chain=[]
            )
    
    def test_decision_helpers(self):
        """Test decision helper methods"""
        blocked = SecurityResult(
            decision=SecurityDecision.BLOCK,
            confidence=1.0, threat_score=1.0,
            matched_patterns=[], reasoning_chain=[]
        )
        assert blocked.is_blocked() is True
        assert blocked.requires_review() is False
        
        review = SecurityResult(
            decision=SecurityDecision.REVIEW,
            confidence=0.7, threat_score=0.6,
            matched_patterns=[], reasoning_chain=[]
        )
        assert review.requires_review() is True
        assert review.is_blocked() is False
        
        sanitized = SecurityResult(
            decision=SecurityDecision.SANITIZE,
            confidence=0.8, threat_score=0.4,
            matched_patterns=[], reasoning_chain=[],
            sanitized_text="cleaned text"
        )
        assert sanitized.is_sanitized() is True
    
    def test_get_final_text(self):
        """Test get_final_text method"""
        original = "original text"
        
        # Blocked result
        blocked = SecurityResult(
            decision=SecurityDecision.BLOCK,
            confidence=1.0, threat_score=1.0,
            matched_patterns=[], reasoning_chain=[]
        )
        assert blocked.get_final_text(original) == "I can't assist with that request."
        
        # Review result
        review = SecurityResult(
            decision=SecurityDecision.REVIEW,
            confidence=0.7, threat_score=0.6,
            matched_patterns=[], reasoning_chain=[]
        )
        assert "requires additional review" in review.get_final_text(original)
        
        # Sanitized result
        sanitized = SecurityResult(
            decision=SecurityDecision.SANITIZE,
            confidence=0.8, threat_score=0.4,
            matched_patterns=[], reasoning_chain=[],
            sanitized_text="cleaned text"
        )
        assert sanitized.get_final_text(original) == "cleaned text"
        
        # Allowed result
        allowed = SecurityResult(
            decision=SecurityDecision.ALLOW,
            confidence=0.9, threat_score=0.1,
            matched_patterns=[], reasoning_chain=[]
        )
        assert allowed.get_final_text(original) == original


class TestSecurityContext:
    """Test SecurityContext dataclass"""
    
    def test_context_creation(self):
        """Test creating security contexts"""
        context = SecurityContext(
            usage_context="educational",
            user_type="student",
            session_id="test123",
            metadata={"course": "security101"}
        )
        
        assert context.usage_context == "educational"
        assert context.user_type == "student"
        assert context.session_id == "test123"
        assert context.metadata["course"] == "security101"
    
    def test_context_helpers(self):
        """Test context helper methods"""
        edu_context = SecurityContext(usage_context="educational")
        assert edu_context.is_educational() is True
        assert edu_context.is_production() is False
        
        research_context = SecurityContext(usage_context="research")
        assert research_context.is_educational() is True
        
        prod_context = SecurityContext(usage_context="production")
        assert prod_context.is_production() is True
        assert prod_context.is_educational() is False
        
        live_context = SecurityContext(usage_context="live")
        assert live_context.is_production() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
