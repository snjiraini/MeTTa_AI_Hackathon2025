#!/usr/bin/env python3
"""
Unit Tests for Configuration Management

Tests the configuration system including YAML loading, environment variable
overrides, validation, and error handling.
"""

import os
import tempfile
import yaml
import pytest
from pathlib import Path

from src.config import SecurityConfig, ConfigManager


class TestSecurityConfig:
    """Test SecurityConfig dataclass validation and behavior"""
    
    def test_default_config_valid(self):
        """Test that default configuration is valid"""
        config = SecurityConfig()
        config.validate()  # Should not raise
    
    def test_threshold_validation(self):
        """Test threshold ordering validation"""
        # Valid thresholds
        config = SecurityConfig(
            sanitize_threshold=0.2,
            review_threshold=0.5,
            block_threshold=0.8
        )
        config.validate()  # Should not raise
        
        # Invalid threshold ordering
        with pytest.raises(ValueError, match="Thresholds must be ordered"):
            config = SecurityConfig(
                sanitize_threshold=0.8,
                review_threshold=0.5,
                block_threshold=0.2
            )
            config.validate()
        
        # Thresholds out of range
        with pytest.raises(ValueError, match="Thresholds must be ordered"):
            config = SecurityConfig(block_threshold=1.5)
            config.validate()
    
    def test_severity_level_validation(self):
        """Test severity level validation"""
        # Missing required severity
        with pytest.raises(ValueError, match="Missing required severity levels"):
            config = SecurityConfig(severity_levels={"ALLOW": 0, "BLOCK": 1})
            config.validate()
        
        # Wrong ordering
        with pytest.raises(ValueError, match="Severity levels must be ordered"):
            config = SecurityConfig(severity_levels={
                "ALLOW": 3, "REVIEW": 2, "SANITIZE": 1, "BLOCK": 0
            })
            config.validate()
    
    def test_performance_validation(self):
        """Test performance setting validation"""
        # Invalid processing time
        with pytest.raises(ValueError, match="max_processing_time_ms must be positive"):
            config = SecurityConfig(max_processing_time_ms=-100)
            config.validate()
        
        # Invalid cache size
        with pytest.raises(ValueError, match="pattern_cache_size must be positive"):
            config = SecurityConfig(pattern_cache_size=0)
            config.validate()


class TestConfigManager:
    """Test ConfigManager YAML and environment loading"""
    
    def test_load_default_config_no_file(self):
        """Test loading with no config file - should use defaults"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigManager(config_file=f"{tmpdir}/nonexistent.yaml")
            config = manager.load_config()
            
            # Should have default values
            assert config.block_threshold == 0.8
            assert config.enable_symbolic_reasoning is True
    
    def test_load_config_from_yaml(self):
        """Test loading configuration from YAML file"""
        config_data = {
            "block_threshold": 0.9,
            "review_threshold": 0.6,
            "sanitize_threshold": 0.4,
            "enable_symbolic_reasoning": False,
            "pattern_weights": {
                "jailbreak": 0.8,
                "escape_codes": 0.7
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            config = manager.load_config()
            
            assert config.block_threshold == 0.9
            assert config.review_threshold == 0.6
            assert config.sanitize_threshold == 0.4
            assert config.enable_symbolic_reasoning is False
            assert config.pattern_weights["jailbreak"] == 0.8
        finally:
            os.unlink(config_file)
    
    def test_environment_variable_override(self):
        """Test environment variable overrides"""
        # Set environment variables
        os.environ["SECURITY_GUARD_BLOCK_THRESHOLD"] = "0.95"
        os.environ["SECURITY_GUARD_ENABLE_SYMBOLIC_REASONING"] = "false"
        os.environ["SECURITY_GUARD_LOG_LEVEL"] = "DEBUG"
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                manager = ConfigManager(config_file=f"{tmpdir}/nonexistent.yaml")
                config = manager.load_config()
                
                # Environment should override defaults
                assert config.block_threshold == 0.95
                assert config.enable_symbolic_reasoning is False
                assert config.logging["level"] == "DEBUG"
        finally:
            # Clean up environment
            for key in ["SECURITY_GUARD_BLOCK_THRESHOLD", 
                       "SECURITY_GUARD_ENABLE_SYMBOLIC_REASONING",
                       "SECURITY_GUARD_LOG_LEVEL"]:
                if key in os.environ:
                    del os.environ[key]
    
    def test_yaml_and_env_precedence(self):
        """Test that environment variables override YAML"""
        config_data = {
            "block_threshold": 0.7,
            "enable_symbolic_reasoning": True
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config_data, f)
            config_file = f.name
        
        # Set conflicting environment variable
        os.environ["SECURITY_GUARD_BLOCK_THRESHOLD"] = "0.9"
        
        try:
            manager = ConfigManager(config_file=config_file)
            config = manager.load_config()
            
            # Environment should win
            assert config.block_threshold == 0.9
            # YAML should still apply where no env override
            assert config.enable_symbolic_reasoning is True
        finally:
            os.unlink(config_file)
            if "SECURITY_GUARD_BLOCK_THRESHOLD" in os.environ:
                del os.environ["SECURITY_GUARD_BLOCK_THRESHOLD"]
    
    def test_invalid_yaml_handling(self):
        """Test handling of invalid YAML files"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: content: [unclosed")
            config_file = f.name
        
        try:
            manager = ConfigManager(config_file=config_file)
            with pytest.raises(ValueError, match="Failed to load config file"):
                manager.load_config()
        finally:
            os.unlink(config_file)
    
    def test_get_config_caching(self):
        """Test that get_config caches the result"""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ConfigManager(config_file=f"{tmpdir}/nonexistent.yaml")
            
            config1 = manager.get_config()
            config2 = manager.get_config()
            
            # Should be the same instance (cached)
            assert config1 is config2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
