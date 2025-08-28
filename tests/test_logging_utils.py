#!/usr/bin/env python3
"""
Unit Tests for Logging and Monitoring

Tests the logging system, performance monitoring, and statistics collection.
"""

import os
import tempfile
import json
import logging
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.config import SecurityConfig
from src.core_types import SecurityResult, SecurityDecision, SecurityContext
from src.logging_utils import SecurityLogger, performance_timer


class TestSecurityLogger:
    """Test SecurityLogger functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test_security.log"
        
        self.config = SecurityConfig(
            logging={
                "level": "DEBUG",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": str(self.log_file),
                "max_file_size_mb": 1
            },
            enable_detailed_logging=True
        )
        
        self.logger = SecurityLogger(self.config)
    
    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_logger_initialization(self):
        """Test logger initialization and setup"""
        assert self.logger.config == self.config
        assert self.logger.logger.name == "security_guard"
        assert len(self.logger.logger.handlers) == 2  # file + console
        
        # Check log directory was created
        assert self.log_file.parent.exists()
    
    def test_log_security_decision(self):
        """Test logging security decisions"""
        # Create test result
        result = SecurityResult(
            decision=SecurityDecision.BLOCK,
            confidence=0.9,
            threat_score=0.8,
            matched_patterns=[],
            reasoning_chain=[],
            processing_time_ms=50.0
        )
        
        context = SecurityContext(
            usage_context="test",
            user_type="test_user"
        )
        
        # Log the decision
        self.logger.log_security_decision("test input", result, context)
        
        # Check statistics updated
        stats = self.logger.get_statistics()
        assert stats["total_requests"] == 1
        assert stats["blocked_requests"] == 1
        assert stats["avg_processing_time_ms"] == 50.0
    
    def test_statistics_tracking(self):
        """Test statistics tracking across multiple requests"""
        # Log different decision types
        decisions = [
            (SecurityDecision.BLOCK, 30.0),
            (SecurityDecision.ALLOW, 20.0),
            (SecurityDecision.SANITIZE, 40.0),
            (SecurityDecision.REVIEW, 60.0)
        ]
        
        for decision, processing_time in decisions:
            result = SecurityResult(
                decision=decision,
                confidence=0.8,
                threat_score=0.5,
                matched_patterns=[],
                reasoning_chain=[],
                processing_time_ms=processing_time
            )
            self.logger.log_security_decision("test", result)
        
        # Check statistics
        stats = self.logger.get_statistics()
        assert stats["total_requests"] == 4
        assert stats["blocked_requests"] == 1
        assert stats["allowed_requests"] == 1
        assert stats["sanitized_requests"] == 1
        assert stats["review_requests"] == 1
        assert stats["block_rate"] == 0.25
        assert stats["allow_rate"] == 0.25
        assert stats["avg_processing_time_ms"] == 37.5  # (30+20+40+60)/4
    
    def test_error_logging(self):
        """Test error logging"""
        test_error = ValueError("Test error message")
        context = {"function": "test_func", "param": "test_value"}
        
        self.logger.log_error(test_error, context)
        
        # Verify log file contains error
        if self.log_file.exists():
            log_content = self.log_file.read_text()
            assert "Security guard error" in log_content
            assert "Test error message" in log_content
    
    def test_performance_metrics_logging(self):
        """Test performance metrics logging"""
        # Generate some activity first
        result = SecurityResult(
            decision=SecurityDecision.ALLOW,
            confidence=0.9,
            threat_score=0.1,
            matched_patterns=[],
            reasoning_chain=[],
            processing_time_ms=25.0
        )
        self.logger.log_security_decision("test", result)
        
        # Log performance metrics
        self.logger.log_performance_metrics()
        
        # Should not crash and should have logged something
        stats = self.logger.get_statistics()
        assert stats["total_requests"] > 0
    
    def test_empty_statistics(self):
        """Test statistics when no requests processed"""
        stats = self.logger.get_statistics()
        assert stats["total_requests"] == 0
        
        # Performance metrics on empty stats should not crash
        self.logger.log_performance_metrics()


class TestPerformanceTimer:
    """Test performance timing utilities"""
    
    def test_performance_timer_basic(self):
        """Test basic performance timer functionality"""
        with performance_timer() as timer:
            # Simulate some work
            import time
            time.sleep(0.01)  # 10ms
        
        # Should have measured some time
        assert timer.elapsed_ms > 0
        assert timer.elapsed_ms < 100  # Should be much less than 100ms
    
    def test_performance_timer_exception(self):
        """Test performance timer with exception"""
        with pytest.raises(ValueError):
            with performance_timer() as timer:
                raise ValueError("Test error")
        
        # Timer should still have elapsed time even with exception
        assert timer.elapsed_ms > 0
    
    def test_performance_timer_nested(self):
        """Test nested performance timers"""
        with performance_timer() as outer_timer:
            import time
            time.sleep(0.01)
            
            with performance_timer() as inner_timer:
                time.sleep(0.01)
            
            # Inner timer should have some time
            assert inner_timer.elapsed_ms > 0
        
        # Outer timer should have more time than inner
        assert outer_timer.elapsed_ms >= inner_timer.elapsed_ms


class TestLoggingIntegration:
    """Test logging integration with other components"""
    
    def test_get_logger_global(self):
        """Test global logger access"""
        # Reset the global logger
        import src.logging_utils
        src.logging_utils._global_logger = None
        
        from src.logging_utils import get_logger
        
        logger1 = get_logger()
        logger2 = get_logger()
        
        # Should return same instance (singleton behavior)
        assert logger1 is logger2
    
    def test_structured_logging_format(self):
        """Test that structured data is properly formatted"""
        temp_dir = tempfile.mkdtemp()
        log_file = Path(temp_dir) / "structured_test.log"
        
        try:
            config = SecurityConfig(
                logging={
                    "level": "INFO",
                    "format": "%(message)s",  # Simplified for testing
                    "file": str(log_file),
                    "max_file_size_mb": 1
                },
                enable_detailed_logging=True
            )
            
            logger = SecurityLogger(config)
            
            # Log a decision with structured data
            result = SecurityResult(
                decision=SecurityDecision.REVIEW,
                confidence=0.7,
                threat_score=0.6,
                matched_patterns=[],
                reasoning_chain=[],
                processing_time_ms=35.0
            )
            
            logger.log_security_decision("test input", result)
            
            # Should have created log file
            assert log_file.exists()
            
        finally:
            import shutil
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
