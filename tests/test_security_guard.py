#!/usr/bin/env python3
"""
Unit Tests for Security Guard Core Functionality

Tests the main SecurityGuard class including prompt/response analysis,
error handling, statistics, and health checks.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import patch, Mock

import pytest

from src.security_guard import SecurityGuard
from src.config import SecurityConfig
from src.core_types import SecurityDecision, SecurityContext


class TestSecurityGuard:
    """Test SecurityGuard main functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = Path(self.temp_dir) / "test_guard.log"
        
        self.config = SecurityConfig(
            logging={
                "level": "DEBUG",
                "format": "%(message)s",
                "file": str(self.log_file),
                "max_file_size_mb": 1
            }
        )
        
        # Reset global logger state
        import src.logging_utils
        src.logging_utils._global_logger = None
        
        # Create guard with test config
        self.guard = SecurityGuard(config=self.config)
    
    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_guard_initialization(self):
        """Test security guard initialization"""
        assert self.guard.config == self.config
        assert self.guard.logger is not None
        assert self.guard._initialization_time > 0
    
    def test_guard_prompt_basic(self):
        """Test basic prompt guarding (Phase 1 implementation)"""
        result = self.guard.guard_prompt("Hello, how are you?")
        
        # Phase 1 should allow all prompts
        assert result.decision == SecurityDecision.ALLOW
        assert result.confidence == 0.5  # Phase 1 basic implementation
        assert result.threat_score == 0.0
        assert len(result.reasoning_chain) == 1
        assert result.reasoning_chain[0].rule_name == "phase1_basic"
        assert result.processing_time_ms > 0
    
    def test_guard_response_basic(self):
        """Test basic response guarding (Phase 1 implementation)"""
        result = self.guard.guard_response("I'm doing well, thank you!")
        
        # Phase 1 should allow all responses
        assert result.decision == SecurityDecision.ALLOW
        assert result.confidence == 0.5  # Phase 1 basic implementation
        assert result.threat_score == 0.0
        assert len(result.reasoning_chain) == 1
        assert result.reasoning_chain[0].rule_name == "phase1_basic"
        assert result.processing_time_ms > 0
    
    def test_guard_prompt_with_context(self):
        """Test prompt guarding with security context"""
        context = SecurityContext(
            usage_context="educational",
            user_type="student",
            session_id="test123"
        )
        
        result = self.guard.guard_prompt("Explain firewalls", context)
        
        # Should still allow in Phase 1
        assert result.decision == SecurityDecision.ALLOW
        assert result.metadata["input_length"] == len("Explain firewalls")
    
    def test_error_handling_prompt(self):
        """Test error handling in prompt analysis"""
        # Mock an error in the analysis method
        with patch.object(self.guard, '_analyze_prompt_basic') as mock_analyze:
            mock_analyze.side_effect = ValueError("Test error")
            
            result = self.guard.guard_prompt("test input")
            
            # Should fail secure
            assert result.decision == SecurityDecision.BLOCK
            assert result.confidence == 1.0
            assert result.threat_score == 1.0
            assert "error" in result.metadata
            assert result.reasoning_chain[0].rule_name == "error_handler"
    
    def test_error_handling_response(self):
        """Test error handling in response analysis"""
        # Mock an error in the analysis method
        with patch.object(self.guard, '_analyze_response_basic') as mock_analyze:
            mock_analyze.side_effect = RuntimeError("Test error")
            
            result = self.guard.guard_response("test response")
            
            # Should fail secure
            assert result.decision == SecurityDecision.BLOCK
            assert result.confidence == 1.0
            assert result.threat_score == 1.0
            assert "error" in result.metadata
    
    def test_statistics_tracking(self):
        """Test statistics collection"""
        # Process some requests
        self.guard.guard_prompt("test 1")
        self.guard.guard_response("response 1") 
        self.guard.guard_prompt("test 2")
        
        stats = self.guard.get_statistics()
        
        # Should have basic stats
        assert stats["total_requests"] == 3
        assert stats["uptime_seconds"] > 0
        assert stats["config_version"] == "phase1"
        assert "components_loaded" in stats
        
        # Phase 1 components should not be loaded yet
        assert stats["components_loaded"]["pattern_matcher"] is False
        assert stats["components_loaded"]["symbolic_reasoner"] is False
        assert stats["components_loaded"]["sanitizer"] is False
    
    def test_health_check(self):
        """Test system health check"""
        health = self.guard.health_check()
        
        assert health["status"] == "healthy"
        assert health["uptime_seconds"] > 0
        assert health["components"]["config"] == "loaded"
        assert health["components"]["logger"] == "active"
        
        # Phase 1 components should show as not implemented
        assert health["components"]["pattern_matcher"] == "not_implemented"
        assert health["components"]["symbolic_reasoner"] == "not_implemented"
        assert health["components"]["sanitizer"] == "not_implemented"
    
    def test_health_check_with_performance(self):
        """Test health check includes performance data after requests"""
        # Generate some requests first
        self.guard.guard_prompt("test")
        self.guard.guard_response("response")
        
        health = self.guard.health_check()
        
        # Should include performance metrics
        assert "performance" in health
        assert health["performance"]["total_requests"] == 2
        assert health["performance"]["avg_processing_time_ms"] > 0
        assert "error_rate" in health["performance"]
    
    def test_config_reload(self):
        """Test configuration reload functionality"""
        # Mock the global config function
        new_config = SecurityConfig(block_threshold=0.95)
        
        with patch('src.security_guard.get_config') as mock_get_config:
            mock_get_config.return_value = new_config
            
            self.guard.reload_config()
            
            # Config should be updated
            assert self.guard.config.block_threshold == 0.95
    
    def test_config_reload_error(self):
        """Test configuration reload error handling"""
        with patch('src.security_guard.get_config') as mock_get_config:
            mock_get_config.side_effect = ValueError("Config error")
            
            with pytest.raises(ValueError):
                self.guard.reload_config()
    
    def test_concurrent_requests(self):
        """Test handling multiple concurrent-like requests"""
        import concurrent.futures
        import threading
        
        results = []
        
        def make_request(request_id):
            result = self.guard.guard_prompt(f"test request {request_id}")
            results.append(result)
        
        # Simulate concurrent requests
        threads = []
        for i in range(5):
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Should have processed all requests
        assert len(results) == 5
        
        # All should be allowed in Phase 1
        for result in results:
            assert result.decision == SecurityDecision.ALLOW
    
    def test_logging_integration(self):
        """Test that security decisions are properly logged"""
        # Process a request
        result = self.guard.guard_prompt("test logging")
        
        # Logger should have recorded the request
        stats = self.guard.logger.get_statistics()
        assert stats["total_requests"] == 1
        assert stats["allowed_requests"] == 1
    
    def test_performance_timing(self):
        """Test that performance timing is working"""
        result = self.guard.guard_prompt("test timing")
        
        # Should have measured some processing time
        assert result.processing_time_ms > 0
        assert result.processing_time_ms < 1000  # Should be very fast for Phase 1


class TestSecurityGuardDefaultConfig:
    """Test SecurityGuard with default configuration"""
    
    def test_default_initialization(self):
        """Test initialization with default config"""
        with patch('src.security_guard.get_config') as mock_get_config:
            mock_config = SecurityConfig()
            mock_get_config.return_value = mock_config
            
            guard = SecurityGuard()
            assert guard.config == mock_config
    
    def test_global_logger_integration(self):
        """Test integration with global logger"""
        with patch('src.security_guard.get_config') as mock_get_config:
            mock_get_config.return_value = SecurityConfig()
            
            with patch('src.security_guard.get_logger') as mock_get_logger:
                mock_logger = Mock()
                mock_get_logger.return_value = mock_logger
                
                guard = SecurityGuard()
                assert guard.logger == mock_logger


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
