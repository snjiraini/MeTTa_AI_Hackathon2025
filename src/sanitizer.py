#!/usr/bin/env python3
"""
Text Sanitization for MeTTa LLM Security Guard

This module provides text sanitization capabilities for removing or neutralizing
dangerous content while preserving the original meaning when possible.

Key features:
- ANSI escape sequence removal (priority from garak findings)
- Terminal control sequence neutralization
- Safe text transformation with content preservation
- Configurable sanitization policies
"""

import re
import html
import unicodedata
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

from .core_types import PatternMatch, SecurityDecision
from .config import SecurityConfig


@dataclass
class SanitizationRule:
    """
    Definition of a text sanitization rule
    
    Rules define how specific threats should be neutralized while
    preserving as much original content as possible.
    """
    name: str                    # Rule identifier
    pattern: str                 # Regex pattern to match
    replacement: str             # Replacement text/pattern
    description: str             # Human-readable description
    preserve_length: bool = False # Whether to preserve original text length


class TextSanitizer:
    """
    Advanced text sanitizer with configurable threat neutralization
    
    This class provides comprehensive text sanitization capabilities
    focusing on ANSI escape sequences and other terminal manipulation
    attempts discovered through security research.
    """
    
    def __init__(self, config: SecurityConfig):
        """
        Initialize text sanitizer with configuration
        
        Args:
            config: Security configuration for sanitization policies
        """
        self.config = config
        
        # Sanitization rules storage
        self._rules: List[SanitizationRule] = []
        self._compiled_rules: Dict[str, re.Pattern] = {}
        
        # Statistics tracking
        self._sanitization_count = 0
        self._total_characters_sanitized = 0
        
        # Initialize built-in sanitization rules
        self._initialize_builtin_rules()
    
    def _initialize_builtin_rules(self) -> None:
        """Initialize built-in sanitization rules based on security findings"""
        
        # ANSI Escape Sequence Rules (High Priority - from garak findings)
        ansi_rules = [
            SanitizationRule(
                name="ansi_escape_sequences",
                pattern=r"\x1b\[[0-9;]*[A-Za-z]",
                replacement="",
                description="Remove ANSI escape sequences for colors and formatting"
            ),
            SanitizationRule(
                name="ansi_escape_literal",
                pattern=r"\\x1b\[[0-9;]*[A-Za-z]|\\033\[[0-9;]*[A-Za-z]|\\u001b\[[0-9;]*[A-Za-z]",
                replacement="",
                description="Remove literal ANSI escape sequence representations"
            ),
            SanitizationRule(
                name="terminal_bell",
                pattern=r"\x07|\\x07|\\a",
                replacement="",
                description="Remove terminal bell characters"
            ),
            SanitizationRule(
                name="cursor_control",
                pattern=r"\x1b\[[ABCD]|\x1b\[[0-9]+[ABCD]",
                replacement="",
                description="Remove cursor movement control sequences"
            ),
            SanitizationRule(
                name="screen_control",
                pattern=r"\x1b\[2J|\x1b\[H|\x1b\[[0-9]+;[0-9]+H",
                replacement="",
                description="Remove screen clearing and positioning sequences"
            )
        ]
        
        # OSC (Operating System Command) Sequence Rules
        osc_rules = [
            SanitizationRule(
                name="osc_hyperlinks",
                pattern=r"\x1b\]8;[^;]*;[^\x07]*\x07",
                replacement="[HYPERLINK REMOVED]",
                description="Replace OSC hyperlink sequences with safe placeholder"
            ),
            SanitizationRule(
                name="osc_title_set",
                pattern=r"\x1b\]0;[^\x07]*\x07",
                replacement="",
                description="Remove window title setting sequences"
            ),
            SanitizationRule(
                name="osc_sequences_general",
                pattern=r"\x1b\][0-9]*;[^\x07]*\x07",
                replacement="",
                description="Remove general OSC sequences"
            )
        ]
        
        # VT100 Control Sequence Rules
        vt100_rules = [
            SanitizationRule(
                name="vt100_reset",
                pattern=r"\x1b\[0m|\x1bc",
                replacement="",
                description="Remove VT100 reset sequences"
            ),
            SanitizationRule(
                name="vt100_formatting",
                pattern=r"\x1b\[[0-9;]*m",
                replacement="",
                description="Remove VT100 text formatting sequences"
            ),
            SanitizationRule(
                name="device_control",
                pattern=r"\x1bP[^\x1b]*\x1b\\",
                replacement="",
                description="Remove Device Control String sequences"
            )
        ]
        
        # Unicode and Special Character Rules
        unicode_rules = [
            SanitizationRule(
                name="null_characters",
                pattern=r"\x00",
                replacement="",
                description="Remove null characters"
            ),
            SanitizationRule(
                name="control_characters",
                pattern=r"[\x01-\x08\x0B-\x0C\x0E-\x1F\x7F]",
                replacement="",
                description="Remove non-printable control characters"
            ),
            SanitizationRule(
                name="unicode_bidi_override",
                pattern=r"[\u202A-\u202E\u2066-\u2069]",
                replacement="",
                description="Remove Unicode bidirectional text override characters"
            )
        ]
        
        # HTML/XML Injection Rules (for web contexts)
        html_rules = [
            SanitizationRule(
                name="script_tags",
                pattern=r"<script[^>]*>.*?</script>",
                replacement="[SCRIPT REMOVED]",
                description="Remove script tags and content"
            ),
            SanitizationRule(
                name="html_events",
                pattern=r"\s+on\w+\s*=\s*[\"'][^\"']*[\"']",
                replacement="",
                description="Remove HTML event handlers"
            )
        ]
        
        # Add all rules to the sanitizer
        all_rules = ansi_rules + osc_rules + vt100_rules + unicode_rules + html_rules
        
        for rule in all_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: SanitizationRule) -> None:
        """
        Add a sanitization rule to the sanitizer
        
        Args:
            rule: SanitizationRule to add
            
        Raises:
            ValueError: If rule pattern compilation fails
        """
        try:
            # Compile regex pattern for performance
            compiled = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            
            # Store rule and compiled version
            self._rules.append(rule)
            self._compiled_rules[rule.name] = compiled
            
        except re.error as e:
            raise ValueError(f"Failed to compile sanitization rule '{rule.name}': {e}")
    
    def sanitize_text(
        self, 
        text: str, 
        matches: Optional[List[PatternMatch]] = None
    ) -> Tuple[str, Dict[str, any]]:
        """
        Sanitize text by applying all sanitization rules
        
        Args:
            text: Text to sanitize
            matches: Optional pattern matches to guide sanitization
            
        Returns:
            Tuple of (sanitized_text, sanitization_metadata)
        """
        if not text:
            return text, {"rules_applied": [], "characters_removed": 0}
        
        sanitized = text
        rules_applied = []
        original_length = len(text)
        
        # Apply sanitization rules in order
        for rule in self._rules:
            compiled_rule = self._compiled_rules.get(rule.name)
            if not compiled_rule:
                continue
            
            # Check if this rule applies to current matches
            if matches and not self._rule_applies_to_matches(rule, matches):
                continue
            
            # Apply the sanitization rule
            before_length = len(sanitized)
            sanitized, rule_applied = self._apply_rule(sanitized, rule, compiled_rule)
            
            if rule_applied:
                rules_applied.append({
                    "rule_name": rule.name,
                    "description": rule.description,
                    "characters_removed": before_length - len(sanitized)
                })
        
        # Update statistics
        characters_removed = original_length - len(sanitized)
        if characters_removed > 0:
            self._sanitization_count += 1
            self._total_characters_sanitized += characters_removed
        
        # Prepare metadata
        metadata = {
            "rules_applied": rules_applied,
            "characters_removed": characters_removed,
            "original_length": original_length,
            "final_length": len(sanitized),
            "sanitization_ratio": characters_removed / original_length if original_length > 0 else 0.0
        }
        
        return sanitized, metadata
    
    def _apply_rule(
        self, 
        text: str, 
        rule: SanitizationRule, 
        compiled_pattern: re.Pattern
    ) -> Tuple[str, bool]:
        """
        Apply a single sanitization rule to text
        
        Args:
            text: Text to process
            rule: Sanitization rule to apply
            compiled_pattern: Pre-compiled regex pattern
            
        Returns:
            Tuple of (processed_text, rule_was_applied)
        """
        original_text = text
        
        if rule.preserve_length:
            # Replace matches while preserving text length
            def replacement_func(match):
                return "*" * len(match.group())
            
            text = compiled_pattern.sub(replacement_func, text)
        else:
            # Standard replacement
            text = compiled_pattern.sub(rule.replacement, text)
        
        rule_applied = text != original_text
        return text, rule_applied
    
    def _rule_applies_to_matches(
        self, 
        rule: SanitizationRule, 
        matches: List[PatternMatch]
    ) -> bool:
        """
        Determine if a sanitization rule applies to the given pattern matches
        
        Args:
            rule: Sanitization rule to check
            matches: Pattern matches found in text
            
        Returns:
            True if rule should be applied based on matches
        """
        # If no matches, apply all rules
        if not matches:
            return True
        
        # Check if any matches indicate this rule should apply
        rule_categories = {
            "ansi_escape_sequences": ["escape_codes"],
            "ansi_escape_literal": ["escape_codes"],
            "terminal_bell": ["escape_codes"],
            "cursor_control": ["escape_codes"],
            "screen_control": ["escape_codes"],
            "osc_hyperlinks": ["escape_codes"],
            "osc_title_set": ["escape_codes"],
            "script_tags": ["harmful_content"],
            "html_events": ["harmful_content"]
        }
        
        applicable_categories = rule_categories.get(rule.name, [])
        if not applicable_categories:
            return True  # Apply rule if no specific categories defined
        
        # Check if any matches are in applicable categories
        for match in matches:
            if match.pattern.category in applicable_categories:
                return True
        
        return False
    
    def sanitize_ansi_sequences(self, text: str) -> str:
        """
        Specialized method for ANSI sequence sanitization
        
        This is a high-performance method specifically for removing
        ANSI escape sequences identified in garak security findings.
        
        Args:
            text: Text potentially containing ANSI sequences
            
        Returns:
            Text with ANSI sequences removed
        """
        if not text:
            return text
        
        # Comprehensive ANSI sequence removal
        patterns = [
            r"\x1b\[[0-9;]*[A-Za-z]",     # Standard ANSI sequences
            r"\x1b\][^\x07]*\x07",        # OSC sequences
            r"\x1b\([AB01]",               # Character set selection
            r"\x1b[=>]",                   # Keypad modes
            r"\x1b[78]",                   # Save/restore cursor
            r"\x1bc",                      # Full reset
            r"\x07",                       # Bell character
        ]
        
        sanitized = text
        for pattern in patterns:
            sanitized = re.sub(pattern, "", sanitized)
        
        # Also remove literal representations
        literal_patterns = [
            r"\\x1b\[[0-9;]*[A-Za-z]",
            r"\\033\[[0-9;]*[A-Za-z]", 
            r"\\u001b\[[0-9;]*[A-Za-z]",
            r"\\x07",
            r"\\a"
        ]
        
        for pattern in literal_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def validate_sanitized_text(self, original: str, sanitized: str) -> Dict[str, any]:
        """
        Validate that sanitization preserved content appropriately
        
        Args:
            original: Original text before sanitization
            sanitized: Text after sanitization
            
        Returns:
            Validation results with safety metrics
        """
        # Calculate content preservation metrics
        original_words = set(original.lower().split())
        sanitized_words = set(sanitized.lower().split())
        
        preserved_words = len(sanitized_words & original_words)
        total_original_words = len(original_words)
        word_preservation_ratio = preserved_words / total_original_words if total_original_words > 0 else 1.0
        
        # Check for remaining dangerous patterns
        dangerous_patterns = [
            r"\x1b",           # Any remaining escape sequences
            r"<script",        # Script tags
            r"javascript:",    # JavaScript URLs
            r"\x00",          # Null characters
        ]
        
        remaining_threats = []
        for pattern in dangerous_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                remaining_threats.append(pattern)
        
        # Calculate safety score
        length_change_ratio = abs(len(sanitized) - len(original)) / len(original) if len(original) > 0 else 0.0
        safety_score = 1.0 - (len(remaining_threats) * 0.3) - (length_change_ratio * 0.2)
        safety_score = max(0.0, min(1.0, safety_score))
        
        return {
            "word_preservation_ratio": word_preservation_ratio,
            "length_change_ratio": length_change_ratio,
            "remaining_threats": remaining_threats,
            "safety_score": safety_score,
            "is_safe": len(remaining_threats) == 0 and safety_score >= 0.7
        }
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get sanitization performance statistics
        
        Returns:
            Dictionary with sanitization metrics
        """
        return {
            "total_rules": len(self._rules),
            "sanitizations_performed": self._sanitization_count,
            "total_characters_sanitized": self._total_characters_sanitized,
            "average_characters_per_sanitization": (
                self._total_characters_sanitized / self._sanitization_count 
                if self._sanitization_count > 0 else 0.0
            ),
            "rules_by_type": self._get_rules_by_type()
        }
    
    def _get_rules_by_type(self) -> Dict[str, int]:
        """Get count of rules by type/category"""
        rule_types = {}
        
        for rule in self._rules:
            # Categorize rules by pattern type
            if "ansi" in rule.name.lower() or "escape" in rule.name.lower():
                category = "ansi_sequences"
            elif "osc" in rule.name.lower():
                category = "osc_sequences"
            elif "vt100" in rule.name.lower():
                category = "vt100_sequences"
            elif "html" in rule.name.lower() or "script" in rule.name.lower():
                category = "html_injection"
            elif "unicode" in rule.name.lower() or "control" in rule.name.lower():
                category = "unicode_control"
            else:
                category = "other"
            
            rule_types[category] = rule_types.get(category, 0) + 1
        
        return rule_types
