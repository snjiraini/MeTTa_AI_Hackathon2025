#!/usr/bin/env python3
"""
Core Security Guard Implementation - Phase 3 Advanced Reasoning
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
from .context_analyzer import ContextAwareAnalyzer, EnhancedSecurityResult


class SecurityGuard:
    """Main Security Guard class providing modular LLM security protection"""
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """Initialize Security Guard with configuration"""
        self.config = config or get_config()
        self.logger = get_logger()
        
        # Initialize Phase 2 components
        self._pattern_matcher = PatternMatcher(self.config)
        self._sanitizer = TextSanitizer(self.config)
        
        # Initialize Phase 3 components
        self._context_analyzer = ContextAwareAnalyzer(self._pattern_matcher)
        self._phase = 3  # Current implementation phase
        
        # Performance tracking
        self._initialization_time = time.time()
        
        self.logger.logger.info("Security Guard initialized with Phase 3 Advanced Reasoning")
    
    def guard_prompt(self, user_prompt: str, context: Optional[SecurityContext] = None, 
                     metadata: Dict[str, Any] = None) -> SecurityResult:
        """Analyze user prompt for security threats using Phase 3 advanced reasoning"""
        with performance_timer() as timer:
            try:
                # Use Phase 3 enhanced analysis
                enhanced_result = self._context_analyzer.enhanced_analyze(
                    user_prompt, metadata or {}, context
                )
                
                # Convert to SecurityResult for backward compatibility
                result = self._convert_enhanced_result(enhanced_result)
                
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
    
    def guard_response(self, model_output: str, context: Optional[SecurityContext] = None,
                      metadata: Dict[str, Any] = None) -> SecurityResult:
        """Analyze model response for security threats using Phase 3 advanced reasoning"""
        with performance_timer() as timer:
            try:
                # Use Phase 3 enhanced analysis
                enhanced_result = self._context_analyzer.enhanced_analyze(
                    model_output, metadata or {}, context
                )
                
                # Convert to SecurityResult for backward compatibility
                result = self._convert_enhanced_result(enhanced_result)
                
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
        if self._context_analyzer:
            stats["context_analyzer"] = self._context_analyzer.get_statistics()
        
        stats.update({
            "initialization_time": self._initialization_time,
            "uptime_seconds": time.time() - self._initialization_time,
            "config_version": "phase3_advanced_reasoning",
            "phase": 3,
            "components_loaded": {
                "pattern_matcher": self._pattern_matcher is not None,
                "text_sanitizer": self._sanitizer is not None,
                "context_analyzer": self._context_analyzer is not None,
                "symbolic_reasoning": True
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
    
    def _convert_enhanced_result(self, enhanced_result: EnhancedSecurityResult) -> SecurityResult:
        """
        Convert EnhancedSecurityResult to SecurityResult for backward compatibility
        
        Args:
            enhanced_result: Phase 3 enhanced result
            
        Returns:
            Compatible SecurityResult
        """
        # Extract sanitized text if available
        sanitized_text = None
        sanitization_metadata = None
        
        if enhanced_result.decision == SecurityDecision.SANITIZE:
            # Use sanitizer to get sanitized version
            original_metadata = enhanced_result.metadata.get("original_metadata", {})
            if "sanitized_text" in original_metadata:
                sanitized_text = original_metadata["sanitized_text"]
                sanitization_metadata = original_metadata.get("sanitization_metadata")
        
        # Create backward-compatible metadata
        compatible_metadata = {
            "phase": 3,
            "analysis_type": "context_aware_symbolic_reasoning",
            "input_length": enhanced_result.metadata.get("input_length", 0),
            "patterns_found": len(enhanced_result.matched_patterns),
            "context_type": enhanced_result.context_analysis.context_type.value,
            "context_confidence": enhanced_result.context_analysis.confidence,
            "symbolic_facts_count": len(enhanced_result.symbolic_facts),
            "sanitized_text": sanitized_text,
            "sanitization_metadata": sanitization_metadata
        }
        
        return SecurityResult(
            decision=enhanced_result.decision,
            confidence=enhanced_result.confidence,
            threat_score=enhanced_result.threat_score,
            matched_patterns=enhanced_result.matched_patterns,
            reasoning_chain=enhanced_result.reasoning_chain,
            processing_time_ms=enhanced_result.processing_time_ms,
            metadata=compatible_metadata
        )
    
    # Phase 3 specific methods
    
    def analyze_with_context(self, text: str, context_metadata: Dict[str, Any]) -> EnhancedSecurityResult:
        """
        Direct access to Phase 3 enhanced analysis
        
        Args:
            text: Text to analyze
            context_metadata: Context metadata for analysis
            
        Returns:
            Enhanced security result with full Phase 3 capabilities
        """
        return self._context_analyzer.enhanced_analyze(text, context_metadata)
    
    def add_context_patterns(self, context_type: str, patterns: List[str]):
        """
        Add new context detection patterns
        
        Args:
            context_type: Type of context (educational, research, etc.)
            patterns: List of regex patterns for detection
        """
        from .context_analyzer import ContextType
        
        try:
            context_enum = ContextType(context_type.lower())
            pattern_dict = {context_enum: patterns}
            self._context_analyzer.update_context_patterns(pattern_dict)
            self.logger.logger.info(f"Added {len(patterns)} patterns for context {context_type}")
        except ValueError:
            self.logger.logger.warning(f"Invalid context type: {context_type}")
    
    def add_reasoning_rule(self, rule_name: str, premises: List[str], conclusion: str, 
                          confidence: float = 1.0, description: str = ""):
        """
        Add custom reasoning rule to the symbolic engine
        
        Args:
            rule_name: Unique rule identifier
            premises: List of logical premises
            conclusion: Rule conclusion
            confidence: Rule confidence level
            description: Human-readable description
        """
        self._context_analyzer.add_reasoning_rule(
            rule_name, premises, conclusion, confidence, description
        )
        self.logger.logger.info(f"Added reasoning rule: {rule_name}")
    
    def get_enhanced_statistics(self) -> Dict[str, Any]:
        """Get comprehensive Phase 3 statistics"""
        base_stats = self.get_statistics()
        context_stats = self._context_analyzer.get_statistics()
        
        return {
            **base_stats,
            "phase": 3,
            "context_analyzer": context_stats,
            "advanced_reasoning": True
        }
