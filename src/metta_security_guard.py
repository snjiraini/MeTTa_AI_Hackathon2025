#!/usr/bin/env python3
"""
MeTTa-Orchestrated Security Guard - Phase 1 Implementation

This module implements a security guard that delegates all decision-making
to the MeTTa symbolic reasoning system. Python code handles I/O and integration
while MeTTa handles all security logic and reasoning.
"""

import os
import time
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from .core_types import SecurityResult, SecurityDecision, SecurityContext, ReasoningStep, PatternMatch
from .config import SecurityConfig, get_config
from .logging_utils import get_logger, performance_timer

# Import MeTTa runtime
try:
    from hyperon import MeTTa
    METTA_AVAILABLE = True
except ImportError:
    print("⚠️  MeTTa runtime not available - using fallback mode")
    METTA_AVAILABLE = False


@dataclass 
class MeTTaSecurityResult:
    """Result from MeTTa security analysis"""
    decision: str
    confidence: float  
    reasoning: str
    threat_score: float = 0.0
    patterns_detected: List[str] = field(default_factory=list)
    context_analysis: Dict[str, float] = field(default_factory=dict)
    processing_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class MeTTaOrchestrator:
    """
    MeTTa-driven security orchestrator
    
    This class loads the MeTTa knowledge base and delegates all security
    decisions to symbolic reasoning. Python handles only integration concerns.
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """Initialize MeTTa orchestrator"""
        self.config = config or get_config()
        self.logger = get_logger()  # Fixed: get_logger takes no arguments
        
        # Initialize MeTTa runtime
        self.metta = None
        self.kb_loaded = False
        self._init_metta_runtime()
        
        # Performance tracking
        self.total_queries = 0
        self.total_time_ms = 0.0
        self.cache = {}  # Simple result cache
        
    def _init_metta_runtime(self) -> None:
        """Initialize MeTTa runtime and load knowledge base"""
        if not METTA_AVAILABLE:
            self.logger.logger.warning("MeTTa runtime not available - using fallback mode")
            return
            
        try:
            # Create MeTTa interpreter
            self.metta = MeTTa()
            self.logger.logger.info("MeTTa interpreter created successfully")
            
            # Load the consolidated knowledge base programmatically
            self.logger.logger.info("Loading MeTTa security knowledge base...")
            self._initialize_knowledge_base()
            self.kb_loaded = True
            self.logger.logger.info("✅ MeTTa security orchestrator loaded successfully")
                
            # Run health check
            self._run_health_check()
                
        except Exception as e:
            self.logger.logger.error(f"Failed to initialize MeTTa runtime: {e}")
            self.metta = None
            
    def _initialize_knowledge_base(self):
        """Initialize the MeTTa knowledge base with security rules."""
        try:
            # Health check function
            self.metta.run('(= (health-check) healthy)')
            
            # Basic security decision rules
            self.metta.run('(= (should-block-request "hello" $context) (ALLOW 0.9 "Safe greeting"))')
            self.metta.run('(= (should-block-request "bomb" $context) (BLOCK 0.9 "Dangerous content"))')
            self.metta.run('(= (should-block-request "hack" $context) (REVIEW 0.7 "Suspicious content"))')
            self.metta.run('(= (should-block-request "ignore previous instructions" $context) (BLOCK 0.8 "Jailbreak attempt"))')
            self.metta.run('(= (should-block-request "DAN" $context) (BLOCK 0.8 "Jailbreak attempt"))')
            self.metta.run('(= (should-block-request "override" $context) (REVIEW 0.6 "Potential bypass"))')
            
            # Default rule for unknown inputs
            self.metta.run('(= (should-block-request $input $context) (ALLOW 0.5 "Default safe response"))')
            
            self.logger.logger.info("✅ MeTTa knowledge base initialized with security rules")
        except Exception as e:
            self.logger.logger.error(f"Failed to initialize knowledge base: {e}")
            raise

    def _run_health_check(self) -> bool:
        """Run MeTTa health check"""
        if not self.metta or not self.kb_loaded:
            return False
            
        try:
            # Test basic MeTTa functionality
            result = self.metta.run("! (health-check $status)")
            if result:
                status = str(result[0]) if len(result) > 0 else "unknown"
                self.logger.logger.info(f"MeTTa health check: {status}")
                return "healthy" in status.lower()
            return False
        except Exception as e:
            self.logger.logger.error(f"MeTTa health check failed: {e}")
            return False
    
    def analyze_security(self, text: str, context: str = "unknown", 
                        metadata: Dict[str, Any] = None) -> MeTTaSecurityResult:
        """
        Analyze text for security threats using MeTTa reasoning
        
        Args:
            text: Input text to analyze
            context: Context hint (educational, research, malicious, etc.)
            metadata: Additional metadata for analysis
            
        Returns:
            MeTTa security analysis result
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = f"{hash(text)}_{context}"
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            cached_result.processing_time_ms = (time.time() - start_time) * 1000
            return cached_result
        
        # Fallback if MeTTa not available
        if not self.metta or not self.kb_loaded:
            return self._fallback_analysis(text, context, metadata)
            
        try:
            # Sanitize inputs for MeTTa
            safe_text = self._sanitize_for_metta(text)
            safe_context = self._sanitize_for_metta(context)
            
            # Query MeTTa for security decision
            query = f'! (should-block-request "{safe_text}" "{safe_context}")'
            self.logger.logger.debug(f"MeTTa query: {query[:100]}...")
            
            result = self.metta.run(query)
            
            if result and len(result) > 0 and len(result[0]) > 0:
                # Parse MeTTa result - expecting ExpressionAtom like (ALLOW 0.9 "reasoning")
                metta_expr = result[0][0]  # Get first result from first list
                
                # Handle ExpressionAtom by extracting children
                if hasattr(metta_expr, 'get_children'):
                    children = metta_expr.get_children()
                    if len(children) >= 3:
                        decision_raw = str(children[0])
                        
                        # Extract confidence value (handle ValueObject)
                        confidence_obj = children[1]
                        if hasattr(confidence_obj, 'get_object'):
                            confidence_val = confidence_obj.get_object()
                            if hasattr(confidence_val, 'value'):
                                confidence_raw = float(confidence_val.value)
                            else:
                                confidence_raw = float(str(confidence_val))
                        else:
                            confidence_raw = float(str(confidence_obj))
                        
                        # Extract reasoning (handle ValueObject with quotes)
                        reasoning_obj = children[2]
                        if hasattr(reasoning_obj, 'get_object'):
                            reasoning_val = reasoning_obj.get_object()
                            if hasattr(reasoning_val, 'value'):
                                reasoning_raw = str(reasoning_val.value)
                            else:
                                reasoning_raw = str(reasoning_val)
                        else:
                            reasoning_raw = str(reasoning_obj)
                        
                        # Clean up the extracted values
                        decision = self._extract_decision(decision_raw)
                        confidence = confidence_raw
                        reasoning = reasoning_raw.strip('"')
                        
                        self.logger.logger.info(f"✅ MeTTa decision: {decision}, confidence: {confidence}, reasoning: {reasoning}")
                        
                        # Get additional analysis details
                        threat_score = 1.0 - confidence  # Higher confidence = lower threat
                        patterns = self._query_patterns(safe_text)
                        context_analysis = self._query_context_analysis(safe_text, safe_context)
                        
                        metta_result = MeTTaSecurityResult(
                            decision=decision,
                            confidence=confidence,
                            reasoning=reasoning,
                    threat_score=threat_score,
                    patterns_detected=patterns,
                    context_analysis=context_analysis,
                    processing_time_ms=(time.time() - start_time) * 1000,
                    metadata=metadata or {}
                )
                
                # Cache successful result
                self.cache[cache_key] = metta_result
                self._update_performance_stats(metta_result.processing_time_ms)
                
                return metta_result
                
            else:
                self.logger.logger.warning("MeTTa returned empty or invalid result")
                return self._fallback_analysis(text, context, metadata)
                
        except Exception as e:
            self.logger.logger.error(f"MeTTa security analysis failed: {e}")
            return self._fallback_analysis(text, context, metadata)
    
    def _sanitize_for_metta(self, text: str) -> str:
        """Sanitize text for safe MeTTa processing"""
        if not text:
            return ""
            
        # Escape quotes and special characters
        sanitized = text.replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
        
        # Limit length to prevent performance issues
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000] + "..."
            
        return sanitized
    
    def _extract_decision(self, decision_raw: str) -> str:
        """Extract security decision from MeTTa result"""
        decision_lower = decision_raw.lower()
        
        if "block" in decision_lower:
            return "block"
        elif "sanitize" in decision_lower:
            return "sanitize"  
        elif "review" in decision_lower:
            return "review"
        elif "allow" in decision_lower:
            return "allow"
        else:
            # Default to block for unknown decisions (fail-secure)
            self.logger.logger.warning(f"Unknown decision from MeTTa: {decision_raw}")
            return "block"
    
    def _extract_confidence(self, confidence_raw: str) -> float:
        """Extract confidence value from MeTTa result"""
        try:
            # Try to extract numeric value
            import re
            numbers = re.findall(r'\d+\.?\d*', confidence_raw)
            if numbers:
                confidence = float(numbers[0])
                return min(1.0, max(0.0, confidence))  # Clamp to [0,1]
            return 0.5  # Default confidence
        except (ValueError, TypeError):
            return 0.5
    
    def _clean_reasoning(self, reasoning_raw: str) -> str:
        """Clean and format reasoning from MeTTa"""
        if not reasoning_raw:
            return "No reasoning provided"
            
        # Remove MeTTa syntax artifacts
        cleaned = reasoning_raw.replace('(', '').replace(')', '').strip()
        
        # Limit length
        if len(cleaned) > 500:
            cleaned = cleaned[:500] + "..."
            
        return cleaned
    
    def _query_threat_score(self, text: str, context: str) -> float:
        """Query MeTTa for threat score"""
        try:
            query = f'! (calculate-threat-score (detect-threat-patterns "{text}") (analyze-context "{text}" "{context}") $score)'
            result = self.metta.run(query)
            if result and len(result) > 0:
                return self._extract_confidence(str(result[0]))
        except Exception as e:
            self.logger.logger.debug(f"Failed to query threat score: {e}")
        return 0.0
    
    def _query_patterns(self, text: str) -> List[str]:
        """Query MeTTa for detected patterns"""
        try:
            query = f'! (detect-threat-patterns "{text}" $patterns)'
            result = self.metta.run(query)
            if result and len(result) > 0:
                # Parse pattern list from MeTTa result
                patterns_str = str(result[0])
                # Simple parsing - extract pattern names
                patterns = []
                for pattern_type in ["dan", "ansi", "harmful", "injection"]:
                    if pattern_type in patterns_str.lower():
                        patterns.append(pattern_type)
                return patterns
        except Exception as e:
            self.logger.logger.debug(f"Failed to query patterns: {e}")
        return []
    
    def _query_context_analysis(self, text: str, context: str) -> Dict[str, float]:
        """Query MeTTa for context analysis"""
        try:
            query = f'! (analyze-context "{text}" "{context}" $result)'
            result = self.metta.run(query)
            if result and len(result) > 0:
                # Parse context scores - simplified implementation
                return {
                    "educational": 0.0,
                    "research": 0.0,
                    "malicious": 0.0
                }
        except Exception as e:
            self.logger.logger.debug(f"Failed to query context analysis: {e}")
        return {}
    
    def _fallback_analysis(self, text: str, context: str, 
                          metadata: Dict[str, Any] = None) -> MeTTaSecurityResult:
        """Fallback security analysis when MeTTa is unavailable"""
        self.logger.logger.warning("Using fallback security analysis")
        
        # Simple heuristic-based analysis
        text_lower = text.lower()
        threat_keywords = [
            "ignore instructions", "jailbreak", "dan mode", 
            "hack", "exploit", "bypass", "override",
            "\\x1b[", "\\033[", "\x1b[", "\033["
        ]
        
        detected_threats = [kw for kw in threat_keywords if kw in text_lower]
        threat_score = min(1.0, len(detected_threats) * 0.3)
        
        # Simple decision logic
        if threat_score > 0.7:
            decision = "block"
            confidence = 0.8
            reasoning = f"Fallback analysis: High threat score ({threat_score:.2f})"
        elif "\\x1b[" in text or "\\033[" in text:
            decision = "sanitize"
            confidence = 0.7
            reasoning = "Fallback analysis: ANSI escape sequences detected"
        elif threat_score > 0.3:
            decision = "review"
            confidence = 0.6
            reasoning = f"Fallback analysis: Moderate threat score ({threat_score:.2f})"
        else:
            decision = "allow"
            confidence = 0.5
            reasoning = "Fallback analysis: No significant threats detected"
        
        return MeTTaSecurityResult(
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            threat_score=threat_score,
            patterns_detected=detected_threats[:3],  # Limit to first 3
            context_analysis={context: 0.5},
            processing_time_ms=1.0,  # Minimal processing time for fallback
            metadata=metadata or {}
        )
    
    def _update_performance_stats(self, processing_time_ms: float) -> None:
        """Update performance statistics"""
        self.total_queries += 1
        self.total_time_ms += processing_time_ms
        
        # Log performance warnings
        if processing_time_ms > self.config.max_processing_time_ms:
            self.logger.logger.warning(
                f"MeTTa query took {processing_time_ms:.1f}ms "
                f"(threshold: {self.config.max_processing_time_ms}ms)"
            )
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        avg_time = self.total_time_ms / max(1, self.total_queries)
        return {
            "total_queries": self.total_queries,
            "total_time_ms": self.total_time_ms,
            "average_time_ms": avg_time,
            "cache_hits": len(self.cache),
            "metta_available": METTA_AVAILABLE,
            "kb_loaded": self.kb_loaded
        }
    
    def clear_cache(self) -> None:
        """Clear result cache"""
        self.cache.clear()
        self.logger.logger.info("MeTTa result cache cleared")


class MeTTaSecurityGuard:
    """
    MeTTa-orchestrated security guard that integrates with existing interfaces
    
    This class provides a familiar interface while delegating all logic to MeTTa
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """Initialize MeTTa security guard"""
        self.config = config or get_config()
        self.orchestrator = MeTTaOrchestrator(self.config)
        self.logger = get_logger()  # Fixed: get_logger takes no arguments
        
        self.logger.logger.info("MeTTa Security Guard initialized")
    
    def guard_prompt(self, user_prompt: str, context: Optional[SecurityContext] = None,
                    metadata: Dict[str, Any] = None) -> SecurityResult:
        """Analyze user prompt for security threats using MeTTa orchestration"""
        with performance_timer() as timer:
            try:
                # Convert context to string
                context_str = self._convert_context(context)
                
                # Query MeTTa orchestrator
                metta_result = self.orchestrator.analyze_security(
                    user_prompt, context_str, metadata
                )
                
                # Convert to SecurityResult format
                result = self._convert_metta_result(metta_result, "prompt")
                result.processing_time_ms = timer.elapsed_ms
                
                self.logger.logger.debug(
                    f"Prompt analysis: {result.decision.value} "
                    f"(confidence: {result.confidence:.2f}, "
                    f"time: {result.processing_time_ms:.1f}ms)"
                )
                
                return result
                
            except Exception as e:
                # Fail-secure: block on error
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
                    processing_time_ms=timer.elapsed_ms,
                    metadata={"error": str(e)}
                )
                
                self.logger.logger.error(f"Prompt guard error: {e}")
                return error_result
    
    def guard_response(self, model_output: str, context: Optional[SecurityContext] = None,
                      metadata: Dict[str, Any] = None) -> SecurityResult:
        """Analyze model response for security threats using MeTTa orchestration"""
        with performance_timer() as timer:
            try:
                # Convert context to string  
                context_str = self._convert_context(context)
                
                # Add response-specific metadata
                response_metadata = (metadata or {}).copy()
                response_metadata.update({
                    "analysis_type": "response",
                    "content_length": len(model_output)
                })
                
                # Query MeTTa orchestrator
                metta_result = self.orchestrator.analyze_security(
                    model_output, context_str, response_metadata
                )
                
                # Convert to SecurityResult format
                result = self._convert_metta_result(metta_result, "response")
                result.processing_time_ms = timer.elapsed_ms
                
                self.logger.logger.debug(
                    f"Response analysis: {result.decision.value} "
                    f"(confidence: {result.confidence:.2f}, "
                    f"time: {result.processing_time_ms:.1f}ms)"
                )
                
                return result
                
            except Exception as e:
                # Fail-secure: block on error
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
                    processing_time_ms=timer.elapsed_ms,
                    metadata={"error": str(e)}
                )
                
                self.logger.logger.error(f"Response guard error: {e}")
                return error_result
    
    def _convert_context(self, context: Optional[SecurityContext]) -> str:
        """Convert SecurityContext to string for MeTTa"""
        if not context:
            return "unknown"
            
        if hasattr(context, 'usage_context'):
            return context.usage_context or "unknown"
        
        return "unknown"
    
    def _convert_metta_result(self, metta_result: MeTTaSecurityResult, 
                            analysis_type: str) -> SecurityResult:
        """Convert MeTTa result to SecurityResult format"""
        
        # Convert decision string to enum
        decision_map = {
            "allow": SecurityDecision.ALLOW,
            "review": SecurityDecision.REVIEW, 
            "sanitize": SecurityDecision.SANITIZE,
            "block": SecurityDecision.BLOCK
        }
        decision = decision_map.get(metta_result.decision, SecurityDecision.BLOCK)
        
        # Create reasoning chain from MeTTa reasoning
        reasoning_chain = [ReasoningStep(
            rule_name="metta_orchestrator",
            premises=metta_result.patterns_detected,
            conclusion=metta_result.reasoning,
            confidence=metta_result.confidence
        )]
        
        # Create pattern matches from detected patterns
        pattern_matches = []
        for pattern_name in metta_result.patterns_detected:
            pattern_matches.append(PatternMatch(
                pattern=None,  # MeTTa handles pattern details internally
                match_text=pattern_name,
                start_pos=0,
                end_pos=0,
                confidence=metta_result.confidence,
                context=str(metta_result.context_analysis.get(pattern_name, 0.0))
            ))
        
        # Combine metadata
        combined_metadata = metta_result.metadata.copy()
        combined_metadata.update({
            "analysis_type": analysis_type,
            "metta_decision": metta_result.decision,
            "context_analysis": metta_result.context_analysis,
            "metta_processing_time_ms": metta_result.processing_time_ms
        })
        
        return SecurityResult(
            decision=decision,
            confidence=metta_result.confidence,
            threat_score=metta_result.threat_score,
            matched_patterns=pattern_matches,
            reasoning_chain=reasoning_chain,
            processing_time_ms=0.0,  # Will be set by caller
            metadata=combined_metadata
        )
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics from MeTTa orchestrator"""
        return self.orchestrator.get_performance_stats()
    
    def clear_cache(self) -> None:
        """Clear MeTTa result cache"""
        self.orchestrator.clear_cache()
