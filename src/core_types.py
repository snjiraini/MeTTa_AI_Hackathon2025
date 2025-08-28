#!/usr/bin/env python3
"""
Core Types and Data Structures for MeTTa LLM Security Guard

This module defines the fundamental data types used throughout the security
guard system, providing type safety and clear interfaces.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class SecurityDecision(Enum):
    """
    Security decision types with clear semantics
    
    These decisions map to the severity levels defined in configuration
    and determine how the security guard handles threats.
    """
    ALLOW = "ALLOW"           # Safe to proceed without modification
    REVIEW = "REVIEW"         # Requires human review before proceeding  
    SANITIZE = "SANITIZE"     # Remove or neutralize dangerous content
    BLOCK = "BLOCK"           # Prevent content from being processed


@dataclass
class ThreatPattern:
    """
    Definition of a security threat pattern
    
    This structure represents a single pattern used to detect security
    threats, with metadata for scoring and categorization.
    """
    name: str                 # Unique pattern identifier
    pattern: str              # Regex or symbolic pattern
    severity: str             # Default severity level (ALLOW/REVIEW/SANITIZE/BLOCK)
    category: str             # Pattern category (jailbreak, escape_codes, etc.)
    weight: float = 1.0       # Pattern importance weight (0.0 to 1.0)
    description: str = ""     # Human-readable description
    
    def __post_init__(self):
        """Validate pattern definition after initialization"""
        if not (0.0 <= self.weight <= 1.0):
            raise ValueError(f"Pattern weight must be 0.0-1.0, got {self.weight}")
        
        if self.severity not in {"ALLOW", "REVIEW", "SANITIZE", "BLOCK"}:
            raise ValueError(f"Invalid severity: {self.severity}")


@dataclass
class PatternMatch:
    """
    Result of pattern matching against input text
    
    Represents a single pattern that matched the input, with context
    about where and how it matched.
    """
    pattern: ThreatPattern    # The pattern that matched
    match_text: str          # The actual text that matched
    start_pos: int           # Start position in input text
    end_pos: int             # End position in input text
    confidence: float        # Match confidence (0.0 to 1.0)
    context: str = ""        # Surrounding text context


@dataclass 
class ReasoningStep:
    """
    Single step in symbolic reasoning chain
    
    Represents one logical step in the MeTTa-based reasoning process,
    allowing for explainable AI decisions.
    """
    rule_name: str           # Name of the rule applied
    premises: List[str]      # Input conditions that triggered the rule
    conclusion: str          # Logical conclusion reached
    confidence: float        # Confidence in this reasoning step
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityResult:
    """
    Complete result of security analysis
    
    This is the primary output structure containing all information
    about a security analysis, including decisions, explanations, and metadata.
    """
    decision: SecurityDecision           # Final security decision
    confidence: float                   # Overall confidence (0.0 to 1.0)
    threat_score: float                 # Numerical threat assessment (0.0 to 1.0)
    matched_patterns: List[PatternMatch] # All patterns that matched
    reasoning_chain: List[ReasoningStep] # Symbolic reasoning steps
    
    # Optional sanitization result
    sanitized_text: Optional[str] = None
    
    # Performance and debugging metadata  
    processing_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate result after initialization"""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be 0.0-1.0, got {self.confidence}")
        
        if not (0.0 <= self.threat_score <= 1.0):
            raise ValueError(f"Threat score must be 0.0-1.0, got {self.threat_score}")
    
    def is_blocked(self) -> bool:
        """Check if this result represents a blocked request"""
        return self.decision == SecurityDecision.BLOCK
    
    def requires_review(self) -> bool:
        """Check if this result requires human review"""
        return self.decision == SecurityDecision.REVIEW
    
    def is_sanitized(self) -> bool:
        """Check if content was sanitized"""
        return self.decision == SecurityDecision.SANITIZE and self.sanitized_text is not None
    
    def get_final_text(self, original_text: str) -> str:
        """
        Get the final text to return to user
        
        Args:
            original_text: The original input text
            
        Returns:
            str: Final text (sanitized if applicable, original if allowed)
        """
        if self.is_sanitized():
            return self.sanitized_text
        elif self.is_blocked():
            return "I can't assist with that request."
        elif self.requires_review():
            return "This request requires additional review before I can respond."
        else:
            return original_text


@dataclass
class SecurityContext:
    """
    Contextual information for security analysis
    
    Provides additional context that can influence security decisions,
    such as user type, usage scenario, or environmental factors.
    """
    usage_context: str = "default"      # Context type (educational, production, etc.)
    user_type: str = "standard"         # User classification
    session_id: Optional[str] = None    # Session identifier for tracking
    timestamp: Optional[float] = None   # Request timestamp
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_educational(self) -> bool:
        """Check if this is an educational context"""
        return self.usage_context.lower() in {"educational", "research", "academic"}
    
    def is_production(self) -> bool:
        """Check if this is a production context"""
        return self.usage_context.lower() in {"production", "live", "customer"}


# Type aliases for cleaner code
ThreatScore = float  # Threat score between 0.0 and 1.0
Confidence = float   # Confidence level between 0.0 and 1.0
