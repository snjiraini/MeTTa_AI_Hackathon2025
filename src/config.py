#!/usr/bin/env python3
"""
Configuration Management for MeTTa LLM Security Guard

This module provides a centralized configuration system supporting:
- YAML-based configuration files
- Environment variable overrides
- Runtime configuration validation
- Type-safe configuration access
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from pathlib import Path


@dataclass
class SecurityConfig:
    """
    Type-safe configuration for security guard system
    
    This dataclass defines all configuration parameters needed for the
    security guard, with sensible defaults and validation.
    """
    
    # Severity levels with numeric values for comparison
    severity_levels: Dict[str, int] = field(default_factory=lambda: {
        "ALLOW": 0,
        "REVIEW": 1, 
        "SANITIZE": 2,
        "BLOCK": 3
    })
    
    # Decision thresholds for automated actions
    block_threshold: float = 0.8
    review_threshold: float = 0.5
    sanitize_threshold: float = 0.3
    
    # Pattern weights for threat scoring
    pattern_weights: Dict[str, float] = field(default_factory=lambda: {
        "jailbreak": 1.0,
        "escape_codes": 0.8,
        "hacking_tools": 0.9,
        "prompt_injection": 0.95
    })
    
    # Feature flags for gradual rollout
    enable_symbolic_reasoning: bool = True
    enable_pattern_learning: bool = False
    enable_detailed_logging: bool = True
    enable_performance_monitoring: bool = True
    
    # Performance settings
    max_processing_time_ms: float = 500
    pattern_cache_size: int = 1000
    enable_parallel_processing: bool = False
    
    # Logging configuration
    logging: Dict[str, Any] = field(default_factory=lambda: {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "logs/security_guard.log",
        "max_file_size_mb": 10
    })
    
    def validate(self) -> None:
        """
        Validate configuration values for consistency and safety
        
        Raises:
            ValueError: If configuration values are invalid
        """
        # Validate threshold ordering
        if not (0 <= self.sanitize_threshold <= self.review_threshold <= self.block_threshold <= 1.0):
            raise ValueError("Thresholds must be ordered: 0 <= sanitize <= review <= block <= 1.0")
        
        # Validate severity levels
        required_severities = {"ALLOW", "REVIEW", "SANITIZE", "BLOCK"}
        if not required_severities.issubset(self.severity_levels.keys()):
            raise ValueError(f"Missing required severity levels: {required_severities - self.severity_levels.keys()}")
        
        # Validate numeric severity ordering
        severities = [(name, level) for name, level in self.severity_levels.items()]
        severities.sort(key=lambda x: x[1])
        expected_order = ["ALLOW", "REVIEW", "SANITIZE", "BLOCK"]
        actual_order = [name for name, _ in severities]
        if actual_order != expected_order:
            raise ValueError(f"Severity levels must be ordered as {expected_order}, got {actual_order}")
        
        # Validate performance settings
        if self.max_processing_time_ms <= 0:
            raise ValueError("max_processing_time_ms must be positive")
        
        if self.pattern_cache_size <= 0:
            raise ValueError("pattern_cache_size must be positive")


class ConfigManager:
    """
    Centralized configuration management with YAML and environment support
    
    This class handles loading configuration from multiple sources with
    proper precedence (environment variables override YAML files).
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_file: Path to YAML configuration file (optional)
        """
        self.config_file = config_file or "config/security_guard.yaml"
        self._config: Optional[SecurityConfig] = None
    
    def load_config(self) -> SecurityConfig:
        """
        Load configuration from YAML file and environment variables
        
        Returns:
            SecurityConfig: Validated configuration object
            
        Raises:
            FileNotFoundError: If required config file doesn't exist
            ValueError: If configuration is invalid
        """
        # Start with default configuration
        config_dict = {}
        
        # Load from YAML file if it exists
        config_path = Path(self.config_file)
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                    if yaml_config:
                        config_dict.update(yaml_config)
            except Exception as e:
                raise ValueError(f"Failed to load config file {self.config_file}: {e}")
        
        # Override with environment variables
        env_overrides = self._load_env_overrides()
        self._deep_update(config_dict, env_overrides)
        
        # Create and validate configuration object
        self._config = SecurityConfig(**config_dict)
        self._config.validate()
        
        return self._config
    
    def get_config(self) -> SecurityConfig:
        """
        Get current configuration, loading if necessary
        
        Returns:
            SecurityConfig: Current validated configuration
        """
        if self._config is None:
            self.load_config()
        return self._config
    
    def _load_env_overrides(self) -> Dict[str, Any]:
        """
        Load configuration overrides from environment variables
        
        Environment variables use the pattern SECURITY_GUARD_<section>_<key>
        Example: SECURITY_GUARD_THRESHOLDS_BLOCK_THRESHOLD=0.9
        
        Returns:
            Dict containing environment variable overrides
        """
        overrides = {}
        env_prefix = "SECURITY_GUARD_"
        
        # Map environment variables to config structure
        env_mappings = {
            f"{env_prefix}BLOCK_THRESHOLD": ("block_threshold", float),
            f"{env_prefix}REVIEW_THRESHOLD": ("review_threshold", float), 
            f"{env_prefix}SANITIZE_THRESHOLD": ("sanitize_threshold", float),
            f"{env_prefix}ENABLE_SYMBOLIC_REASONING": ("enable_symbolic_reasoning", lambda x: x.lower() == 'true'),
            f"{env_prefix}ENABLE_PATTERN_LEARNING": ("enable_pattern_learning", lambda x: x.lower() == 'true'),
            f"{env_prefix}ENABLE_DETAILED_LOGGING": ("enable_detailed_logging", lambda x: x.lower() == 'true'),
            f"{env_prefix}MAX_PROCESSING_TIME_MS": ("max_processing_time_ms", float),
            f"{env_prefix}PATTERN_CACHE_SIZE": ("pattern_cache_size", int),
            f"{env_prefix}LOG_LEVEL": ("logging.level", str),
        }
        
        for env_var, (config_key, type_converter) in env_mappings.items():
            if env_var in os.environ:
                try:
                    value = type_converter(os.environ[env_var])
                    self._set_nested_key(overrides, config_key, value)
                except (ValueError, TypeError) as e:
                    print(f"Warning: Invalid environment variable {env_var}: {e}")
        
        return overrides
    
    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """
        Deep update dictionary with nested structure support
        
        Args:
            base_dict: Dictionary to update
            update_dict: Dictionary with updates
        """
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def _set_nested_key(self, dictionary: Dict[str, Any], key_path: str, value: Any) -> None:
        """
        Set nested dictionary key using dot notation
        
        Args:
            dictionary: Target dictionary
            key_path: Dot-separated key path (e.g., "logging.level")
            value: Value to set
        """
        keys = key_path.split('.')
        current = dictionary
        
        # Navigate to parent of target key
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set final value
        current[keys[-1]] = value


def get_config() -> SecurityConfig:
    """
    Global configuration access function
    
    Returns:
        SecurityConfig: Current system configuration
    """
    global _global_config_manager
    if '_global_config_manager' not in globals():
        _global_config_manager = ConfigManager()
    
    return _global_config_manager.get_config()
