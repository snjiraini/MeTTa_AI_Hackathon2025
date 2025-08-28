#!/usr/bin/env python3
"""
MeTTa LLM Security Guard - Phase 1 Core Infrastructure

This package provides a production-ready security guard system for LLMs
with modular architecture, configuration management, and comprehensive logging.

Phase 1 Components:
- Configuration management with YAML and environment variable support
- Type-safe core data structures
- Comprehensive logging and monitoring
- Modular security guard foundation
- Fail-secure error handling

Usage:
    from src.security_guard import SecurityGuard
    from src.core_types import SecurityContext
    
    # Initialize with default configuration
    guard = SecurityGuard()
    
    # Analyze user prompt
    result = guard.guard_prompt("Hello, how are you?")
    print(f"Decision: {result.decision.value}")
    
    # Analyze with context
    context = SecurityContext(usage_context="educational")
    result = guard.guard_prompt("Explain how firewalls work", context)
"""

from .security_guard import SecurityGuard
from .core_types import (
    SecurityResult, SecurityDecision, SecurityContext,
    ThreatPattern, PatternMatch, ReasoningStep
)
from .config import SecurityConfig, ConfigManager, get_config
from .logging_utils import SecurityLogger, get_logger, performance_timer

__version__ = "1.0.0-phase1"
__author__ = "MeTTa Security Guard Team"

# Export main public interface
__all__ = [
    # Main classes
    "SecurityGuard",
    "SecurityConfig", 
    "ConfigManager",
    "SecurityLogger",
    
    # Core types
    "SecurityResult",
    "SecurityDecision", 
    "SecurityContext",
    "ThreatPattern",
    "PatternMatch",
    "ReasoningStep",
    
    # Utilities
    "get_config",
    "get_logger",
    "performance_timer"
]
