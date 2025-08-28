#!/usr/bin/env python3
"""
Core Security Guard Implementation - Phase 1 Foundation

This module provides the main SecurityGuard class with modular architecture,
configuration management, and comprehensive logging. This is the foundation
for subsequent phases to build upon.
"""

import time
from typing import Optional, List, Dict, Any

from .config import SecurityConfig, get_config
from .core_types import (
    SecurityResult, SecurityDecision, SecurityContext,
    ThreatPattern, PatternMatch, ReasoningStep
)
from .logging_utils import get_logger, performance_timer


class SecurityGuard:
    """
    Main Security Guard class providing modular LLM security protection
    
    This class orchestrates the security analysis pipeline with:
    - Configuration-driven behavior
    - Comprehensive logging and monitoring
    - Fail-secure error handling
    - Modular architecture for extensibility
    """
    
    def __init__(self, config: Optional[SecurityConfig] = None):
        """
        Initialize Security Guard with configuration
        
        Args:
            config: Optional configuration override (uses global config if None)
        """
        self.config = config or get_config()
        self.logger = get_logger()
        
        # Initialize component placeholders for future phases
        self._pattern_matcher = None
        self._symbolic_reasoner = None
        self._sanitizer = None
        
        # Performance tracking
        self._initialization_time = time.time()
        
        self.logger.logger.info(
            "Security Guard initialized",
            extra={
                "structured_data": {
                    "event_type": "initialization",
                    "timestamp": self._initialization_time,
                    "config_summary": {
                        "block_threshold": self.config.block_threshold,
                        "review_threshold": self.config.review_threshold,
                        "sanitize_threshold": self.config.sanitize_threshold,
                        "symbolic_reasoning": self.config.enable_symbolic_reasoning,
                        "detailed_logging": self.config.enable_detailed_logging
                    }
                }
            }
        )
    
    def guard_prompt(
        self, 
        user_prompt: str, 
        context: Optional[SecurityContext] = None
    ) -> SecurityResult:
        """
        Analyze user prompt for security threats
        
        Args:
            user_prompt: User input text to analyze
            context: Optional context information
            
        Returns:
            SecurityResult: Complete analysis result with decision
        """
        with performance_timer() as timer:
            try:
                # Phase 1: Basic implementation with fail-secure behavior
                # Future phases will add pattern matching and symbolic reasoning
                
                result = self._analyze_prompt_basic(user_prompt, context)
                
            except Exception as e:
                # Fail-secure: block on any error
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
                
                self.logger.log_error(e, {
                    "function": "guard_prompt",
                    "input_length": len(user_prompt),
                    "context": context
                })
                
                error_result.processing_time_ms = timer.elapsed_ms
                return error_result
        
        # Set processing time and log the decision
        result.processing_time_ms = timer.elapsed_ms
        self.logger.log_security_decision(user_prompt, result, context)
        
        return result
    
    def guard_response(
        self, 
        model_output: str, 
        context: Optional[SecurityContext] = None
    ) -> SecurityResult:
        """
        Analyze model response for security threats
        
        Args:
            model_output: LLM output text to analyze
            context: Optional context information
            
        Returns:
            SecurityResult: Complete analysis result with decision
        """
        with performance_timer() as timer:
            try:
                # Phase 1: Basic implementation with fail-secure behavior
                # Future phases will add pattern matching and symbolic reasoning
                
                result = self._analyze_response_basic(model_output, context)
                
            except Exception as e:
                # Fail-secure: block on any error
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
                
                self.logger.log_error(e, {
                    "function": "guard_response", 
                    "input_length": len(model_output),
                    "context": context
                })
                
                error_result.processing_time_ms = timer.elapsed_ms
                return error_result
        
        # Set processing time and log the decision
        result.processing_time_ms = timer.elapsed_ms
        self.logger.log_security_decision(model_output, result, context)
        
        return result
    
    def _analyze_prompt_basic(
        self, 
        user_prompt: str, 
        context: Optional[SecurityContext]
    ) -> SecurityResult:
        """
        Basic prompt analysis - Phase 1 implementation
        
        This is a placeholder implementation that always allows prompts.
        Future phases will implement pattern matching and symbolic reasoning.
        
        Args:
            user_prompt: User input to analyze
            context: Optional context
            
        Returns:
            SecurityResult with basic analysis
        """
        # Phase 1: Simple allow-all implementation
        # This will be replaced with sophisticated analysis in later phases
        
        reasoning_steps = [
            ReasoningStep(
                rule_name="phase1_basic",
                premises=["Input received", "No pattern matching enabled"],
                conclusion="Allow by default (Phase 1)",
                confidence=0.5,
                metadata={"phase": 1, "basic_implementation": True}
            )
        ]
        
        return SecurityResult(
            decision=SecurityDecision.ALLOW,
            confidence=0.5,  # Low confidence since this is basic implementation
            threat_score=0.0,
            matched_patterns=[],
            reasoning_chain=reasoning_steps,
            metadata={
                "phase": 1,
                "input_length": len(user_prompt),
                "analysis_type": "basic"
            }
        )
    
    def _analyze_response_basic(
        self, 
        model_output: str, 
        context: Optional[SecurityContext]
    ) -> SecurityResult:
        """
        Basic response analysis - Phase 1 implementation
        
        This is a placeholder implementation that always allows responses.
        Future phases will implement pattern matching and symbolic reasoning.
        
        Args:
            model_output: LLM output to analyze
            context: Optional context
            
        Returns:
            SecurityResult with basic analysis
        """
        # Phase 1: Simple allow-all implementation
        # This will be replaced with sophisticated analysis in later phases
        
        reasoning_steps = [
            ReasoningStep(
                rule_name="phase1_basic",
                premises=["Output received", "No pattern matching enabled"],
                conclusion="Allow by default (Phase 1)",
                confidence=0.5,
                metadata={"phase": 1, "basic_implementation": True}
            )
        ]
        
        return SecurityResult(
            decision=SecurityDecision.ALLOW,
            confidence=0.5,  # Low confidence since this is basic implementation
            threat_score=0.0,
            matched_patterns=[],
            reasoning_chain=reasoning_steps,
            metadata={
                "phase": 1,
                "output_length": len(model_output),
                "analysis_type": "basic"
            }
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current system statistics
        
        Returns:
            Dict containing performance and usage statistics
        """
        stats = self.logger.get_statistics()
        stats.update({
            "initialization_time": self._initialization_time,
            "uptime_seconds": time.time() - self._initialization_time,
            "config_version": "phase1",
            "components_loaded": {
                "pattern_matcher": self._pattern_matcher is not None,
                "symbolic_reasoner": self._symbolic_reasoner is not None,
                "sanitizer": self._sanitizer is not None
            }
        })
        return stats
    
    def reload_config(self) -> None:
        """
        Reload configuration from file
        
        This allows runtime configuration updates without restart.
        """
        try:
            self.config = get_config()
            self.logger.logger.info(
                "Configuration reloaded successfully",
                extra={
                    "structured_data": {
                        "event_type": "config_reload",
                        "timestamp": time.time()
                    }
                }
            )
        except Exception as e:
            self.logger.log_error(e, {"function": "reload_config"})
            raise
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform system health check
        
        Returns:
            Dict containing health status and diagnostics
        """
        health_status = {
            "status": "healthy",
            "timestamp": time.time(),
            "uptime_seconds": time.time() - self._initialization_time,
            "components": {
                "config": "loaded",
                "logger": "active",
                "pattern_matcher": "not_implemented" if self._pattern_matcher is None else "active",
                "symbolic_reasoner": "not_implemented" if self._symbolic_reasoner is None else "active", 
                "sanitizer": "not_implemented" if self._sanitizer is None else "active"
            }
        }
        
        # Add performance metrics
        stats = self.logger.get_statistics()
        if stats.get("total_requests", 0) > 0:
            health_status["performance"] = {
                "total_requests": stats["total_requests"],
                "avg_processing_time_ms": stats["avg_processing_time_ms"],
                "error_rate": 0.0  # Will be calculated from actual error tracking in future phases
            }
        
        return health_status
