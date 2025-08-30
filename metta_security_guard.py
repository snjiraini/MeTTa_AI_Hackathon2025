#!/usr/bin/env python3
"""
MeTTa-Orchestrated Security Guard - Refactored Modular Implementation

This module provides the main interface to the MeTTa security guard system
by importing and orchestrating the modular components. All MeTTa runtime
functionality is delegated to the orchestrator module.
"""

from typing import Dict, Any, List, Optional

# Import modular components
from src.metta_orchestrator import MeTTaOrchestrator, MeTTaSecurityResult
from src.core_types import SecurityResult, SecurityDecision, SecurityContext, ReasoningStep, PatternMatch
from src.config import SecurityConfig, get_config
from src.logging_utils import get_logger, performance_timer

class MeTTaSecurityGuard:
    """
    MeTTa-orchestrated security guard that integrates with existing interfaces
    
    This class provides a familiar interface while delegating all logic to MeTTa
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """Initialize MeTTa security guard"""
        self.config = config or get_config()
        self.orchestrator = MeTTaOrchestrator(self.config)
        self.logger = get_logger()
        
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
