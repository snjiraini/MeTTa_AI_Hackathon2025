#!/usr/bin/env python3
"""
Logging and Monitoring Utilities for MeTTa LLM Security Guard

This module provides structured logging, performance monitoring, and
audit trail capabilities for the security guard system.
"""

import logging
import logging.handlers
import time
import json
from typing import Dict, Any, Optional
from pathlib import Path
from contextlib import contextmanager
from dataclasses import asdict

from .config import SecurityConfig
from .core_types import SecurityResult, SecurityContext


class SecurityLogger:
    """
    Specialized logger for security events with structured output
    
    Provides structured logging for security decisions, performance metrics,
    and audit trails with automatic log rotation and formatting.
    """
    
    def __init__(self, config: SecurityConfig):
        """
        Initialize security logger with configuration
        
        Args:
            config: Security configuration containing logging settings
        """
        self.config = config
        self.logger = logging.getLogger("security_guard")
        self._setup_logging()
        
        # Performance tracking
        self._request_count = 0
        self._total_processing_time = 0.0
        self._blocked_requests = 0
        self._allowed_requests = 0
        self._sanitized_requests = 0
        self._review_requests = 0
    
    def _setup_logging(self) -> None:
        """Configure logging handlers and formatters"""
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Set logging level
        log_level = getattr(logging, self.config.logging["level"].upper(), logging.INFO)
        self.logger.setLevel(log_level)
        
        # Create log directory if needed
        log_file = Path(self.config.logging["file"])
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=self.config.logging["max_file_size_mb"] * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        
        # Setup console handler for development
        console_handler = logging.StreamHandler()
        
        # Create formatter
        formatter = logging.Formatter(self.config.logging["format"])
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Prevent propagation to root logger
        self.logger.propagate = False
    
    def log_security_decision(
        self, 
        input_text: str, 
        result: SecurityResult, 
        context: Optional[SecurityContext] = None
    ) -> None:
        """
        Log a security decision with full context
        
        Args:
            input_text: Original input text
            result: Security analysis result
            context: Optional context information
        """
        # Update statistics
        self._request_count += 1
        self._total_processing_time += result.processing_time_ms
        
        if result.decision.value == "BLOCK":
            self._blocked_requests += 1
        elif result.decision.value == "ALLOW":
            self._allowed_requests += 1
        elif result.decision.value == "SANITIZE":
            self._sanitized_requests += 1
        elif result.decision.value == "REVIEW":
            self._review_requests += 1
        
        # Create structured log entry
        log_data = {
            "event_type": "security_decision",
            "timestamp": time.time(),
            "input_hash": hash(input_text),  # Hash for privacy
            "input_length": len(input_text),
            "decision": result.decision.value,
            "confidence": result.confidence,
            "threat_score": result.threat_score,
            "processing_time_ms": result.processing_time_ms,
            "pattern_matches": len(result.matched_patterns),
            "reasoning_steps": len(result.reasoning_chain),
            "context": asdict(context) if context else None
        }
        
        # Add pattern match details if enabled
        if self.config.enable_detailed_logging:
            log_data["matched_patterns"] = [
                {
                    "name": match.pattern.name,
                    "category": match.pattern.category,
                    "confidence": match.confidence,
                    "match_length": len(match.match_text)
                }
                for match in result.matched_patterns
            ]
            
            log_data["reasoning_chain"] = [
                {
                    "rule": step.rule_name,
                    "conclusion": step.conclusion,
                    "confidence": step.confidence
                }
                for step in result.reasoning_chain
            ]
        
        # Log with appropriate level based on decision
        if result.decision.value == "BLOCK":
            self.logger.warning("Security threat blocked", extra={"structured_data": log_data})
        elif result.decision.value == "REVIEW":
            self.logger.info("Content flagged for review", extra={"structured_data": log_data})
        else:
            self.logger.debug("Security analysis completed", extra={"structured_data": log_data})
    
    def log_performance_metrics(self) -> None:
        """Log current performance metrics"""
        if self._request_count == 0:
            return
        
        avg_processing_time = self._total_processing_time / self._request_count
        
        metrics = {
            "event_type": "performance_metrics",
            "timestamp": time.time(),
            "total_requests": self._request_count,
            "avg_processing_time_ms": avg_processing_time,
            "blocked_requests": self._blocked_requests,
            "allowed_requests": self._allowed_requests,
            "sanitized_requests": self._sanitized_requests,
            "review_requests": self._review_requests,
            "block_rate": self._blocked_requests / self._request_count,
            "allow_rate": self._allowed_requests / self._request_count
        }
        
        self.logger.info("Performance metrics update", extra={"structured_data": metrics})
    
    def log_error(self, error: Exception, context: Dict[str, Any]) -> None:
        """
        Log an error with context information
        
        Args:
            error: Exception that occurred
            context: Additional context about the error
        """
        error_data = {
            "event_type": "error",
            "timestamp": time.time(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context
        }
        
        self.logger.error(f"Security guard error: {error}", extra={"structured_data": error_data})
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get current system statistics
        
        Returns:
            Dict containing current performance and usage statistics
        """
        if self._request_count == 0:
            return {"total_requests": 0}
        
        return {
            "total_requests": self._request_count,
            "avg_processing_time_ms": self._total_processing_time / self._request_count,
            "blocked_requests": self._blocked_requests,
            "allowed_requests": self._allowed_requests,
            "sanitized_requests": self._sanitized_requests,
            "review_requests": self._review_requests,
            "block_rate": self._blocked_requests / self._request_count,
            "allow_rate": self._allowed_requests / self._request_count,
            "sanitize_rate": self._sanitized_requests / self._request_count,
            "review_rate": self._review_requests / self._request_count
        }


@contextmanager
def performance_timer():
    """
    Context manager for timing operations
    
    Usage:
        with performance_timer() as timer:
            # do work
            pass
        elapsed_ms = timer.elapsed_ms
    """
    class Timer:
        def __init__(self):
            self.start_time = time.perf_counter()
            self.elapsed_ms = 0.0
        
        def stop(self):
            self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000
    
    timer = Timer()
    try:
        yield timer
    finally:
        timer.stop()


# Global logger instance - initialized when config is loaded
_global_logger: Optional[SecurityLogger] = None


def get_logger() -> SecurityLogger:
    """
    Get the global security logger instance
    
    Returns:
        SecurityLogger: Configured logger instance
    """
    global _global_logger
    if _global_logger is None:
        from .config import get_config
        config = get_config()
        _global_logger = SecurityLogger(config)
    
    return _global_logger
