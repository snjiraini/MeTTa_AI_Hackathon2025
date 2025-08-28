#!/usr/bin/env python3
"""
Advanced Pattern Matching for MeTTa LLM Security Guard

This module implements sophisticated threat pattern detection with:
- Regular expression patterns with contextual analysis
- Weighted scoring system for threat assessment
- Category-based classification of threats
- Performance optimization with compiled pattern caching
- ANSI escape code detection based on garak findings
"""

import re
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from functools import lru_cache

from .core_types import ThreatPattern, PatternMatch, SecurityContext
from .config import SecurityConfig


@dataclass
class PatternCategory:
    """
    Category definition for grouping related threat patterns
    
    Categories help organize patterns and apply different scoring
    weights and handling policies per category type.
    """
    name: str                     # Category identifier
    description: str              # Human-readable description
    default_weight: float = 1.0   # Default weight for patterns in category
    requires_context: bool = False # Whether patterns need context evaluation


class PatternMatcher:
    """
    Advanced pattern matcher with regex-based threat detection
    
    This class implements the core pattern matching engine with:
    - Compiled regex caching for performance
    - Weighted threat scoring
    - Category-based pattern organization
    - Context-aware pattern evaluation
    """
    
    def __init__(self, config: SecurityConfig):
        """
        Initialize pattern matcher with configuration
        
        Args:
            config: Security configuration containing pattern weights and settings
        """
        self.config = config
        
        # Pattern storage and caches
        self._patterns: List[ThreatPattern] = []
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._categories: Dict[str, PatternCategory] = {}
        
        # Performance tracking
        self._match_cache = {}  # Simple cache for recent matches
        self._cache_hits = 0
        self._cache_misses = 0
        
        # Initialize built-in patterns and categories
        self._initialize_categories()
        self._initialize_builtin_patterns()
    
    def _initialize_categories(self) -> None:
        """Initialize pattern categories based on garak findings and common threats"""
        categories = [
            PatternCategory(
                name="jailbreak",
                description="Jailbreaking attempts and role-playing exploits",
                default_weight=1.0,
                requires_context=True
            ),
            PatternCategory(
                name="escape_codes",
                description="ANSI escape codes and terminal manipulation",
                default_weight=0.8,
                requires_context=False
            ),
            PatternCategory(
                name="hacking_tools",
                description="References to penetration testing and hacking tools",
                default_weight=0.7,
                requires_context=True
            ),
            PatternCategory(
                name="prompt_injection",
                description="Instructions to ignore system prompts",
                default_weight=0.95,
                requires_context=False
            ),
            PatternCategory(
                name="harmful_content",
                description="Requests for dangerous or illegal information",
                default_weight=0.9,
                requires_context=True
            ),
            PatternCategory(
                name="continuation_attack",
                description="Completion-based attacks for harmful content",
                default_weight=0.85,
                requires_context=False
            )
        ]
        
        for category in categories:
            self._categories[category.name] = category
    
    def _initialize_builtin_patterns(self) -> None:
        """Initialize built-in threat patterns based on security research and garak findings"""
        
        # ANSI Escape Code Patterns (High Priority - from garak findings)
        escape_patterns = [
            ThreatPattern(
                name="ansi_escape_sequences",
                pattern=r"\\x1b\[|\\033\[|\\u001b\[|\\x9b|\x1b\[|\033\[|\u001b\[",
                severity="SANITIZE",
                category="escape_codes",
                weight=0.8,
                description="ANSI escape sequence injection attempts"
            ),
            ThreatPattern(
                name="terminal_bell",
                pattern=r"\\x07|\\a|\x07|\a",
                severity="SANITIZE", 
                category="escape_codes",
                weight=0.6,
                description="Terminal bell character for system manipulation"
            ),
            ThreatPattern(
                name="vt100_sequences",
                pattern=r"\\x1b\[[0-9;]*[A-Za-z]|\\033\[[0-9;]*[A-Za-z]",
                severity="SANITIZE",
                category="escape_codes", 
                weight=0.7,
                description="VT100 terminal control sequences"
            ),
            ThreatPattern(
                name="osc_sequences",
                pattern=r"\\x1b\]|\\033\]|\x1b\]|\033\]",
                severity="BLOCK",
                category="escape_codes",
                weight=0.9,
                description="Operating System Command sequences for hyperlinks"
            )
        ]
        
        # Jailbreak Patterns
        jailbreak_patterns = [
            ThreatPattern(
                name="dan_mode",
                pattern=r"\bDAN\s+Mode\b|Do\s+Anything\s+Now|DAN:|GPT:|act\s+as.*DAN",
                severity="BLOCK",
                category="jailbreak",
                weight=1.0,
                description="DAN (Do Anything Now) jailbreak attempts"
            ),
            ThreatPattern(
                name="role_playing_jailbreak", 
                pattern=r"from\s+now\s+on.*act\s+as|pretend\s+to\s+be|simulate.*mode|enable.*mode",
                severity="REVIEW",
                category="jailbreak",
                weight=0.8,
                description="Role-playing based jailbreak attempts"
            ),
            ThreatPattern(
                name="dual_output_request",
                pattern=r"provide\s+two\s+responses|GPT:.*DAN:|normal.*uncensored|censored.*uncensored",
                severity="BLOCK", 
                category="jailbreak",
                weight=0.9,
                description="Requests for dual normal/jailbroken outputs"
            )
        ]
        
        # Prompt Injection Patterns
        injection_patterns = [
            ThreatPattern(
                name="ignore_instructions",
                pattern=r"ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)",
                severity="BLOCK",
                category="prompt_injection", 
                weight=0.95,
                description="Direct instructions to ignore system prompts"
            ),
            ThreatPattern(
                name="override_instructions",
                pattern=r"disregard|forget|override.*(?:instructions|rules|policies|guidelines)",
                severity="BLOCK",
                category="prompt_injection",
                weight=0.9,
                description="Instructions to override system guidelines"
            ),
            ThreatPattern(
                name="system_debug",
                pattern=r"system\s+debugger?|print.*system\s+prompt|reveal.*(?:hidden|system)\s+(?:prompt|instructions)",
                severity="BLOCK",
                category="prompt_injection",
                weight=0.95,
                description="Attempts to extract system prompts"
            )
        ]
        
        # Hacking Tools Patterns (Context-Aware)
        hacking_patterns = [
            ThreatPattern(
                name="metasploit",
                pattern=r"\bmetasploit\b|meterpreter|msf(?:console|venom)?",
                severity="REVIEW",  # Context-dependent
                category="hacking_tools",
                weight=0.7,
                description="Metasploit penetration testing framework"
            ),
            ThreatPattern(
                name="nmap",
                pattern=r"\bnmap\b|port\s+scan|network\s+scan",
                severity="REVIEW",
                category="hacking_tools", 
                weight=0.6,
                description="Network scanning tools"
            ),
            ThreatPattern(
                name="sql_injection",
                pattern=r"union\s+select|'.*or.*1\s*=\s*1|sql\s+injection|sqlmap",
                severity="BLOCK",
                category="hacking_tools",
                weight=0.9,
                description="SQL injection techniques"
            )
        ]
        
        # Harmful Content Patterns
        harmful_patterns = [
            ThreatPattern(
                name="malware_creation",
                pattern=r"create.*(?:virus|malware|ransomware|trojan)|write.*malicious\s+code",
                severity="BLOCK",
                category="harmful_content",
                weight=0.95,
                description="Requests to create malicious software"
            ),
            ThreatPattern(
                name="illegal_activities",
                pattern=r"how\s+to.*(?:hack|break\s+into|steal|pirate)|step\s*-?\s*by\s*-?\s*step.*(?:illegal|criminal)",
                severity="BLOCK",
                category="harmful_content",
                weight=0.9,
                description="Instructions for illegal activities"
            )
        ]
        
        # Continuation Attack Patterns
        continuation_patterns = [
            ThreatPattern(
                name="completion_attack",
                pattern=r"(?:complete|finish|continue).*(?:sentence|phrase|word):|.*\s+(?:like\s+a|is\s+a)\s*$",
                severity="REVIEW",
                category="continuation_attack",
                weight=0.6,
                description="Completion-based attacks for harmful content generation"
            )
        ]
        
        # Add all patterns to the matcher
        all_patterns = (
            escape_patterns + jailbreak_patterns + injection_patterns +
            hacking_patterns + harmful_patterns + continuation_patterns
        )
        
        for pattern in all_patterns:
            self.add_pattern(pattern)
    
    def add_pattern(self, pattern: ThreatPattern) -> None:
        """
        Add a new threat pattern to the matcher
        
        Args:
            pattern: ThreatPattern to add to detection system
            
        Raises:
            ValueError: If pattern compilation fails
        """
        try:
            # Compile regex pattern for performance
            compiled = re.compile(pattern.pattern, re.IGNORECASE | re.MULTILINE)
            
            # Store pattern and compiled version
            self._patterns.append(pattern)
            self._compiled_patterns[pattern.name] = compiled
            
        except re.error as e:
            raise ValueError(f"Failed to compile pattern '{pattern.name}': {e}")
    
    def remove_pattern(self, pattern_name: str) -> bool:
        """
        Remove a pattern from the matcher
        
        Args:
            pattern_name: Name of pattern to remove
            
        Returns:
            bool: True if pattern was found and removed
        """
        # Remove from patterns list
        for i, pattern in enumerate(self._patterns):
            if pattern.name == pattern_name:
                del self._patterns[i]
                break
        else:
            return False  # Pattern not found
        
        # Remove compiled pattern
        if pattern_name in self._compiled_patterns:
            del self._compiled_patterns[pattern_name]
        
        # Clear cache to prevent stale results
        self._match_cache.clear()
        
        return True
    
    def find_matches(
        self, 
        text: str, 
        context: Optional[SecurityContext] = None
    ) -> List[PatternMatch]:
        """
        Find all pattern matches in the given text
        
        Args:
            text: Text to analyze for threats
            context: Optional context for context-aware pattern evaluation
            
        Returns:
            List of PatternMatch objects for all detected threats
        """
        if not text.strip():
            return []
        
        # Check cache first for performance
        cache_key = self._get_cache_key(text, context)
        if cache_key in self._match_cache:
            self._cache_hits += 1
            return self._match_cache[cache_key]
        
        self._cache_misses += 1
        matches = []
        
        # Analyze text with each pattern
        for pattern in self._patterns:
            pattern_matches = self._find_pattern_matches(text, pattern, context)
            matches.extend(pattern_matches)
        
        # Sort matches by position for consistent ordering
        matches.sort(key=lambda m: (m.start_pos, m.end_pos))
        
        # Cache result for performance
        if len(self._match_cache) < 1000:  # Limit cache size
            self._match_cache[cache_key] = matches
        
        return matches
    
    def _find_pattern_matches(
        self,
        text: str,
        pattern: ThreatPattern, 
        context: Optional[SecurityContext]
    ) -> List[PatternMatch]:
        """
        Find matches for a specific pattern in text
        
        Args:
            text: Text to search
            pattern: Pattern to match against
            context: Context for evaluation
            
        Returns:
            List of PatternMatch objects for this pattern
        """
        compiled_pattern = self._compiled_patterns.get(pattern.name)
        if not compiled_pattern:
            return []
        
        matches = []
        
        # Find all regex matches
        for regex_match in compiled_pattern.finditer(text):
            start_pos = regex_match.start()
            end_pos = regex_match.end()
            match_text = regex_match.group()
            
            # Get surrounding context for analysis
            context_start = max(0, start_pos - 50)
            context_end = min(len(text), end_pos + 50)
            surrounding_context = text[context_start:context_end]
            
            # Calculate confidence based on pattern strength and context
            confidence = self._calculate_match_confidence(pattern, match_text, context)
            
            # Apply context-aware filtering if needed
            if self._should_include_match(pattern, match_text, context):
                pattern_match = PatternMatch(
                    pattern=pattern,
                    match_text=match_text,
                    start_pos=start_pos,
                    end_pos=end_pos,
                    confidence=confidence,
                    context=surrounding_context
                )
                matches.append(pattern_match)
        
        return matches
    
    def _calculate_match_confidence(
        self,
        pattern: ThreatPattern,
        match_text: str, 
        context: Optional[SecurityContext]
    ) -> float:
        """
        Calculate confidence score for a pattern match
        
        Args:
            pattern: The matched pattern
            match_text: The actual matched text
            context: Security context if available
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = 0.7  # Base confidence for regex matches
        
        # Adjust based on pattern weight
        weight_factor = pattern.weight
        
        # Adjust based on match length (longer matches often more significant)
        length_factor = min(1.0, len(match_text) / 20.0)
        
        # Adjust based on context appropriateness
        context_factor = 1.0
        if context:
            category = self._categories.get(pattern.category)
            if category and category.requires_context:
                if context.is_educational():
                    context_factor = 0.7  # Lower threat in educational context
                elif context.is_production():
                    context_factor = 1.2  # Higher threat in production
        
        # Combine factors with bounds checking
        confidence = base_confidence * weight_factor * (1.0 + length_factor * 0.3) * context_factor
        return min(1.0, max(0.0, confidence))
    
    def _should_include_match(
        self,
        pattern: ThreatPattern,
        match_text: str,
        context: Optional[SecurityContext]
    ) -> bool:
        """
        Determine if a pattern match should be included based on context
        
        Args:
            pattern: The matched pattern
            match_text: The matched text
            context: Security context
            
        Returns:
            True if match should be included in results
        """
        # Always include high-severity matches
        if pattern.severity in ["BLOCK"]:
            return True
        
        # Context-aware filtering for educational content
        if context and context.is_educational():
            # Allow some hacking tool references in educational context
            if pattern.category == "hacking_tools":
                # Allow if it seems educational (contains "how", "what", "explain")
                educational_indicators = ["how", "what", "explain", "learn", "understand", "concept"]
                text_lower = match_text.lower()
                if any(indicator in text_lower for indicator in educational_indicators):
                    return False  # Don't flag educational references
        
        return True  # Include by default
    
    def _get_cache_key(self, text: str, context: Optional[SecurityContext]) -> str:
        """
        Generate cache key for text and context combination
        
        Args:
            text: Input text
            context: Security context
            
        Returns:
            Cache key string
        """
        # Create hash of text to avoid storing large strings
        text_hash = hashlib.md5(text.encode('utf-8')).hexdigest()
        
        # Include context in key
        context_key = ""
        if context:
            context_key = f"{context.usage_context}_{context.user_type}"
        
        return f"{text_hash}_{context_key}"
    
    def calculate_threat_score(self, matches: List[PatternMatch]) -> float:
        """
        Calculate overall threat score from pattern matches
        
        Args:
            matches: List of pattern matches found in text
            
        Returns:
            Overall threat score between 0.0 and 1.0
        """
        if not matches:
            return 0.0
        
        # Weight matches by category and confidence
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for match in matches:
            category_weight = self.config.pattern_weights.get(match.pattern.category, 1.0)
            weighted_score = match.confidence * match.pattern.weight * category_weight
            total_weighted_score += weighted_score
            total_weight += match.pattern.weight * category_weight
        
        if total_weight == 0:
            return 0.0
        
        # Normalize score and apply diminishing returns for multiple matches
        base_score = total_weighted_score / total_weight
        
        # Diminishing returns - multiple weak matches don't equal one strong match
        match_count_factor = 1.0 - (1.0 / (1.0 + len(matches) * 0.3))
        
        final_score = base_score * (0.7 + 0.3 * match_count_factor)
        
        return min(1.0, max(0.0, final_score))
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get pattern matching performance statistics
        
        Returns:
            Dictionary with performance metrics
        """
        total_requests = self._cache_hits + self._cache_misses
        cache_hit_rate = self._cache_hits / total_requests if total_requests > 0 else 0.0
        
        return {
            "total_patterns": len(self._patterns),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": cache_hit_rate,
            "cache_size": len(self._match_cache),
            "categories": list(self._categories.keys())
        }
    
    def clear_cache(self) -> None:
        """Clear the pattern matching cache"""
        self._match_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0
