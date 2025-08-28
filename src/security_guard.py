#!/usr/bin/env python3
"""
Core Security Guard Implementation - Phase 2 Enhanced Detection
"""

import time
from typing import Optional, List, Dict, Any

from .config import SecurityConfig, get_config
from .core_types import (
    SecurityResult, SecurityDecision, SecurityContext,
    ThreatPattern, PatternMatch, ReasoningStep
)
from .logging_utils import get_logger, performance_timer
from .patterns import PatternMatcher
from .sanitizer import TextSanitizer


class SecurityGuard:
    """Main Security Guard class providing modular LLM security protection"""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """Initialize Security Guard with configuration"""
        self.config = config or get_config()
        self.logger = get_logger()
        
        # Initialize Phase 2 components
        self._pattern_matcher = PatternMatcher(self.config)
        self._sanitizer = TextSanitizer(self.config)
        self._symbolic_reasoner = None
        
        # Performance tracking
        self._initialization_time = time.time()
        
        self.logger.logger.info("Security Guard initialized with Phase 2 enhancements")
    
    def guard_prompt(self, user_prompt: str, context: Optional[SecurityContext] = None) -> SecurityResult:
        """Analyze user prompt for security threats"""
        with performance_timer() as timer:
            try:
                result = self._analyze_prompt_enhanced(user_prompt, context)
            except Exception as e:
                error_result = SecurityResult(
                    decision=SecurityDecision.BLOCK,
                    confidence=1.0,
                    threat_score=1.0,
                    matched_patterns=[],
                    reasoning_chain=[ReasoningStep(
                        rule_name="error_handler",
                        premises=[f"Exception: {type(e).__name__}"],
                        conclusion="Block due to processing error",
                        confidence=1.0
                    )],
                    processing_time_ms=0.0,
                    metadata={"error": str(e)}
                )
                self.logger.log_error(e, {"function": "guard_prompt"})
                error_result.processing_time_ms = timer.elapsed_ms
                return error_result
        
        result.processing_time_ms = timer.elapsed_ms
        self.logger.log_security_decision(user_prompt, result, context)
        return result
    
    def guard_response(self, model_output: str, context: Optional[SecurityContext] = None) -> SecurityResult:
        """Analyze model response for security threats"""
        with performance_timer() as timer:
            try:
                result = self._analyze_response_enhanced(model_output, context)
            except Exception as e:
                error_result = SecurityResult(
                    decision=SecurityDecision.BLOCK,
                    confidence=1.0,
                    threat_score=1.0,
                    matched_patterns=[],
                    reasoning_chain=[ReasoningStep(
                        rule_name="error_handler",
                        premises=[f"Exception: {type(e).__name__}"],
                        conclusion="Block due to processing error",
                        confidence=1.0
                    )],
                    processing_time_ms=0.0,
                    metadata={"error": str(e)}
                )
                self.logger.log_error(e, {"function": "guard_response"})
                error_result.processing_time_ms = timer.elapsed_ms
                return error_result
        
        result.processing_time_ms = timer.elapsed_ms
        self.logger.log_security_decision(model_output, result, context)
        return result
    
    def _analyze_prompt_enhanced(self, user_prompt: str, context: Optional[SecurityContext]) -> SecurityResult:
        """Enhanced prompt analysis with pattern matching"""
        matches = self._pattern_matcher.find_matches(user_prompt)
        threat_score = self._calculate_threat_score(matches)
        decision, confidence, reasoning_steps = self._make_security_decision(
            user_prompt, matches, threat_score, "prompt", context
        )
        
        sanitized_text = None
        sanitization_metadata = None
        if decision == SecurityDecision.SANITIZE:
            sanitized_text, sanitization_metadata = self._sanitizer.sanitize_text(user_prompt, matches)
        
        return SecurityResult(
            decision=decision,
            confidence=confidence,
            threat_score=threat_score,
            matched_patterns=matches,
            reasoning_chain=reasoning_steps,
            metadata={
                "phase": 2,
                "input_length": len(user_prompt),
                "analysis_type": "enhanced_pattern_matching",
                "patterns_found": len(matches),
                "sanitized_text": sanitized_text,
                "sanitization_metadata": sanitization_metadata
            }
        )
    
    def _analyze_response_enhanced(self, model_output: str, context: Optional[SecurityContext]) -> SecurityResult:
        """Enhanced response analysis with pattern matching"""
        matches = self._pattern_matcher.find_matches(model_output)
        threat_score = self._calculate_threat_score(matches)
        decision, confidence, reasoning_steps = self._make_security_decision(
            model_output, matches, threat_score, "response", context
        )
        
        sanitized_text = None
        sanitization_metadata = None
        if decision == SecurityDecision.SANITIZE:
            sanitized_text, sanitization_metadata = self._sanitizer.sanitize_text(model_output, matches)
        
        return SecurityResult(
            decision=decision,
            confidence=confidence,
            threat_score=threat_score,
            matched_patterns=matches,
            reasoning_chain=reasoning_steps,
            metadata={
                "phase": 2,
                "output_length": len(model_output),
                "analysis_type": "enhanced_pattern_matching",
                "patterns_found": len(matches),
                "sanitized_text": sanitized_text,
                "sanitization_metadata": sanitization_metadata
            }
        )
    
    def _calculate_threat_score(self, matches: List[PatternMatch]) -> float:
        """Calculate overall threat score from pattern matches"""
        if not matches:
            return 0.0
        
        # Weight different categories of threats
        category_weights = {
            "jailbreak": 0.9,
            "escape_codes": 0.8,
            "harmful_content": 0.85,
            "continuation_attack": 0.6,
            "prompt_injection": 0.7,
            "hacking_tools": 0.5
        }
        
        total_weighted_score = 0.0
        max_possible_score = 0.0
        
        for match in matches:
            category = match.pattern.category
            weight = category_weights.get(category, 0.5)
            weighted_score = match.confidence * weight
            total_weighted_score += weighted_score
            max_possible_score += weight
        
        if max_possible_score == 0:
            return 0.0
        
        base_score = total_weighted_score / max_possible_score
        match_count_factor = min(1.0, 1.0 - (0.1 * max(0, len(matches) - 3)))
        final_score = base_score * match_count_factor
        return min(1.0, final_score)
    
    def _make_security_decision(self, text: str, matches: List[PatternMatch], threat_score: float, 
                              analysis_type: str, context: Optional[SecurityContext]) -> tuple[SecurityDecision, float, List[ReasoningStep]]:
        """Make security decision based on threat analysis"""
        reasoning_steps = [
            ReasoningStep(
                rule_name="threat_assessment",
                premises=[f"Analyzed {analysis_type}", f"Found {len(matches)} patterns", f"Score: {threat_score:.3f}"],
                conclusion=f"Threat score: {threat_score:.3f}",
                confidence=0.9
            )
        ]
        
        if threat_score >= self.config.block_threshold:
            decision = SecurityDecision.BLOCK
            confidence = 0.95
            reasoning_steps.append(ReasoningStep(
                rule_name="block_threshold",
                premises=[f"Score {threat_score:.3f} >= threshold {self.config.block_threshold}"],
                conclusion="BLOCK - High threat detected",
                confidence=confidence
            ))
        elif threat_score >= self.config.sanitize_threshold:
            if self._can_sanitize_threats(matches):
                decision = SecurityDecision.SANITIZE
                confidence = 0.8
                reasoning_steps.append(ReasoningStep(
                    rule_name="sanitize_threshold",
                    premises=[f"Score {threat_score:.3f} >= sanitize threshold", "Threats can be sanitized"],
                    conclusion="SANITIZE - Removable threats",
                    confidence=confidence
                ))
            else:
                decision = SecurityDecision.BLOCK
                confidence = 0.9
                reasoning_steps.append(ReasoningStep(
                    rule_name="non_sanitizable",
                    premises=["Threats cannot be safely sanitized"],
                    conclusion="BLOCK - Non-sanitizable threats",
                    confidence=confidence
                ))
        elif threat_score >= self.config.review_threshold:
            decision = SecurityDecision.REVIEW
            confidence = 0.7
            reasoning_steps.append(ReasoningStep(
                rule_name="review_threshold",
                premises=[f"Score {threat_score:.3f} >= review threshold"],
                conclusion="REVIEW - Manual review recommended",
                confidence=confidence
            ))
        else:
            decision = SecurityDecision.ALLOW
            confidence = 0.85
            reasoning_steps.append(ReasoningStep(
                rule_name="allow_threshold",
                premises=[f"Score {threat_score:.3f} < review threshold"],
                conclusion="ALLOW - Content appears safe",
                confidence=confidence
            ))
        
        return decision, confidence, reasoning_steps
    
    def _can_sanitize_threats(self, matches: List[PatternMatch]) -> bool:
        """Determine if detected threats can be safely sanitized"""
        sanitizable_categories = {"escape_codes", "hacking_tools", "continuation_attack"}
        non_sanitizable_categories = {"jailbreak", "harmful_content", "prompt_injection"}
        
        for match in matches:
            if match.pattern.category in non_sanitizable_categories and match.confidence > 0.7:
                return False
        
        for match in matches:
            if match.pattern.category in sanitizable_categories:
                return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current system statistics"""
        stats = self.logger.get_statistics()
        
        if self._pattern_matcher:
            stats["pattern_matcher"] = self._pattern_matcher.get_statistics()
        if self._sanitizer:
            stats["text_sanitizer"] = self._sanitizer.get_statistics()
        
        stats.update({
            "initialization_time": self._initialization_time,
            "uptime_seconds": time.time() - self._initialization_time,
            "config_version": "phase2_enhanced",
            "phase": 2,
            "components_loaded": {
                "pattern_matcher": self._pattern_matcher is not None,
                "text_sanitizer": self._sanitizer is not None,
                "symbolic_reasoner": self._symbolic_reasoner is not None
            }
        })
        return stats
    
    def health_check(self) -> Dict[str, Any]:
        """Perform system health check"""
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "uptime_seconds": time.time() - self._initialization_time,
            "phase": 2,
            "components": {
                "config": "loaded",
                "logger": "active",
                "pattern_matcher": "active" if self._pattern_matcher is not None else "not_loaded",
                "text_sanitizer": "active" if self._sanitizer is not None else "not_loaded", 
                "symbolic_reasoner": "not_implemented" if self._symbolic_reasoner is None else "active"
            }
        }
    
    def test_pattern_detection(self, test_text: str) -> Dict[str, Any]:
        """Test pattern detection on given text"""
        if not self._pattern_matcher:
            return {"error": "Pattern matcher not initialized"}
        
        matches = self._pattern_matcher.find_matches(test_text)
        threat_score = self._calculate_threat_score(matches)
        
        return {
            "text": test_text,
            "matches_found": len(matches),
            "threat_score": threat_score,
            "matches": [
                {
                    "pattern_name": match.pattern.name,
                    "category": match.pattern.category,
                    "confidence": match.confidence,
                    "start": match.start,
                    "end": match.end,
                    "matched_text": match.matched_text
                }
                for match in matches
            ]
        }
    
    def test_sanitization(self, test_text: str) -> Dict[str, Any]:
        """Test text sanitization on given text"""
        if not self._sanitizer:
            return {"error": "Text sanitizer not initialized"}
        
        sanitized_text, metadata = self._sanitizer.sanitize_text(test_text)
        
        return {
            "original_text": test_text,
            "sanitized_text": sanitized_text,
            "metadata": metadata
        }
