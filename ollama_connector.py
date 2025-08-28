#!/usr/bin/env python3
"""
Enhanced Ollama Connector - Real Model Integration

This module provides enhanced Ollama model integration with:
1. Real connection to Ollama API with proper error handling
2. Streaming support for better user experience  
3. Integration with the Enhanced Security Gateway
4. Comprehensive logging and monitoring
5. Backward compatibility with existing demo scripts

Key Features:
- Drop-in replacement for existing chat_completion function
- Enhanced error handling and retry logic
- Streaming response support (optional)
- Integration with security gateway
- Performance monitoring and logging
- Connection health checks
"""

import time
import json
import requests
from typing import Dict, Any, List, Optional, Iterator, Tuple
import os
from urllib.parse import urljoin

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    ENHANCED_REQUESTS = True
except ImportError:
    ENHANCED_REQUESTS = False

class OllamaConnector:
    """
    Enhanced Ollama connector with security integration and better error handling
    
    This class provides a robust connection to Ollama while maintaining backward
    compatibility with existing scripts. It integrates seamlessly with the
    Enhanced Security Gateway.
    """
    
    def __init__(self, base_url: str = None, api_key: str = None, timeout: int = 60):
        """
        Initialize Ollama connector
        
        Args:
            base_url: Ollama API base URL (defaults to environment or localhost)
            api_key: API key (defaults to environment or "ollama")  
            timeout: Request timeout in seconds
        """
        self.base_url = base_url or os.getenv("OPENAI_BASE_URL", "http://host.docker.internal:11434/v1")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "ollama")
        self.timeout = timeout
        self.logger_enabled = True
        
        # Remove trailing slash for consistent URL handling
        self.base_url = self.base_url.rstrip('/')
        
        # Create session with retry strategy if available
        self.session = requests.Session()
        if ENHANCED_REQUESTS:
            try:
                retry_strategy = Retry(
                    total=3,
                    status_forcelist=[429, 500, 502, 503, 504],
                    allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],  # Updated parameter name
                    backoff_factor=1
                )
                adapter = HTTPAdapter(max_retries=retry_strategy)
                self.session.mount("http://", adapter)
                self.session.mount("https://", adapter)
            except TypeError:
                # Fallback for older urllib3 versions
                try:
                    retry_strategy = Retry(
                        total=3,
                        status_forcelist=[429, 500, 502, 503, 504],
                        method_whitelist=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"],  # Older parameter name
                        backoff_factor=1
                    )
                    adapter = HTTPAdapter(max_retries=retry_strategy)
                    self.session.mount("http://", adapter)
                    self.session.mount("https://", adapter)
                except Exception as e:
                    self._log(f"⚠️  Could not set up retry strategy: {e}")
                    # Continue without retry strategy
        
        # Connection status
        self._connected = False
        self._last_health_check = 0
        self._health_check_interval = 30  # seconds
        
        self._log(f"✅ Ollama connector initialized: {self.base_url}")
    
    def _log(self, message: str):
        """Simple logging method"""
        if self.logger_enabled:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] OllamaConnector: {message}")
    
    def health_check(self, force: bool = False) -> bool:
        """
        Check if Ollama is available and responsive
        
        Args:
            force: Force health check even if recently checked
            
        Returns:
            True if Ollama is healthy, False otherwise
        """
        current_time = time.time()
        
        # Skip check if recently performed (unless forced)
        if not force and (current_time - self._last_health_check) < self._health_check_interval:
            return self._connected
        
        try:
            # Try to get models list as health check
            health_url = f"{self.base_url}/models"
            response = self.session.get(
                health_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=5  # Shorter timeout for health check
            )
            
            self._connected = response.status_code == 200
            self._last_health_check = current_time
            
            if self._connected:
                self._log("✅ Ollama health check passed")
            else:
                self._log(f"⚠️  Ollama health check failed: HTTP {response.status_code}")
                
        except Exception as e:
            self._connected = False
            self._last_health_check = current_time
            self._log(f"❌ Ollama health check failed: {e}")
        
        return self._connected
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        Get list of available models from Ollama
        
        Returns:
            List of model information dictionaries
        """
        try:
            url = f"{self.base_url}/models"
            response = self.session.get(
                url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            models = data.get("data", []) if "data" in data else data.get("models", [])
            self._log(f"📋 Found {len(models)} available models")
            return models
            
        except Exception as e:
            self._log(f"❌ Failed to list models: {e}")
            return []
    
    def chat_completion(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 512,
        stream: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send chat completion request to Ollama (OpenAI-compatible format)
        
        This method maintains backward compatibility with existing scripts while
        adding enhanced error handling and logging.
        
        Args:
            model: Model name to use
            messages: List of message objects with "role" and "content"
            temperature: Response randomness (0.0-1.0)
            max_tokens: Maximum response tokens
            stream: Whether to stream the response (not implemented yet)
            **kwargs: Additional parameters to pass to the API
            
        Returns:
            JSON response from Ollama API in OpenAI format
            
        Raises:
            requests.HTTPError: If API request fails
            ConnectionError: If Ollama is not available
        """
        # Perform health check before making request
        if not self.health_check():
            raise ConnectionError("Ollama is not available. Please ensure Ollama is running.")
        
        start_time = time.time()
        
        try:
            # Construct API endpoint
            url = f"{self.base_url}/chat/completions"
            
            # Prepare headers
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Prepare request payload in OpenAI format
            payload = {
                "model": model,
                "messages": messages,
                "temperature": float(temperature),
                "max_tokens": int(max_tokens),
                "stream": stream,
                **kwargs
            }
            
            # Log request details
            prompt_text = messages[-1].get("content", "")[:50] if messages else ""
            self._log(f"🚀 Sending request to model '{model}': {prompt_text}...")
            
            # Make the request
            response = self.session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse response
            data = response.json()
            
            # Log response details
            elapsed_time = time.time() - start_time
            response_text = ""
            if "choices" in data and len(data["choices"]) > 0:
                response_text = data["choices"][0].get("message", {}).get("content", "")[:50]
            
            self._log(f"✅ Response received in {elapsed_time:.2f}s: {response_text}...")
            
            return data
            
        except requests.exceptions.Timeout:
            self._log(f"⏰ Request timeout after {self.timeout}s")
            raise
        except requests.exceptions.ConnectionError as e:
            self._log(f"🔌 Connection error: {e}")
            raise ConnectionError(f"Failed to connect to Ollama at {self.base_url}") from e
        except requests.exceptions.HTTPError as e:
            self._log(f"🚫 HTTP error: {e}")
            if hasattr(e.response, 'text'):
                self._log(f"   Error details: {e.response.text[:200]}")
            raise
        except Exception as e:
            self._log(f"❌ Unexpected error: {e}")
            raise
    
    def stream_chat_completion(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 512,
        **kwargs
    ) -> Iterator[Dict[str, Any]]:
        """
        Stream chat completion responses from Ollama
        
        This method provides streaming responses for better user experience
        with long-running requests.
        
        Args:
            model: Model name to use
            messages: List of message objects
            temperature: Response randomness
            max_tokens: Maximum response tokens
            **kwargs: Additional parameters
            
        Yields:
            Dict[str, Any]: Streaming response chunks
        """
        try:
            # Set stream=True and make request
            url = f"{self.base_url}/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": model,
                "messages": messages,
                "temperature": float(temperature),
                "max_tokens": int(max_tokens),
                "stream": True,
                **kwargs
            }
            
            self._log(f"🌊 Starting streaming request to model '{model}'...")
            
            with self.session.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout,
                stream=True
            ) as response:
                response.raise_for_status()
                
                for line in response.iter_lines(decode_unicode=True):
                    if line and line.startswith("data: "):
                        data_str = line[6:]  # Remove "data: " prefix
                        
                        if data_str == "[DONE]":
                            break
                            
                        try:
                            data = json.loads(data_str)
                            yield data
                        except json.JSONDecodeError as e:
                            self._log(f"⚠️  Failed to parse streaming data: {e}")
                            continue
                            
        except Exception as e:
            self._log(f"❌ Streaming error: {e}")
            raise


# Backward compatibility function - drop-in replacement
def chat_completion(
    base_url: str,
    api_key: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float,
    max_tokens: int,
    timeout: int,
) -> Dict[str, Any]:
    """
    Enhanced chat completion function - backward compatible with existing scripts
    
    This function provides a drop-in replacement for the existing chat_completion
    function in run_security_demo.py and other scripts, while adding enhanced
    error handling and logging.
    
    Args:
        base_url: Ollama API base URL
        api_key: API key for authentication
        model: Model name to use
        messages: List of message objects
        temperature: Response randomness
        max_tokens: Maximum response tokens
        timeout: Request timeout in seconds
        
    Returns:
        Dict[str, Any]: JSON response from Ollama API
        
    Raises:
        requests.HTTPError: If API request fails
        ConnectionError: If Ollama is not available
    """
    # Create connector instance and make request
    connector = OllamaConnector(base_url=base_url, api_key=api_key, timeout=timeout)
    return connector.chat_completion(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens
    )


# Enhanced factory function for new usage
def create_ollama_connector(
    base_url: str = None,
    api_key: str = None,
    timeout: int = 60
) -> OllamaConnector:
    """
    Factory function to create an enhanced Ollama connector
    
    Args:
        base_url: Ollama API base URL
        api_key: API key for authentication
        timeout: Request timeout in seconds
        
    Returns:
        OllamaConnector: Enhanced connector instance
    """
    return OllamaConnector(base_url=base_url, api_key=api_key, timeout=timeout)


# Integration test function
def test_ollama_connection():
    """Test the Ollama connection and functionality"""
    print("\n🧪 Testing Enhanced Ollama Connector")
    print("=" * 40)
    
    # Create connector
    connector = create_ollama_connector()
    
    # Test health check
    print("\n🏥 Testing health check...")
    is_healthy = connector.health_check(force=True)
    if is_healthy:
        print("✅ Ollama is healthy and responsive")
    else:
        print("❌ Ollama health check failed")
        return
    
    # Test model listing
    print("\n📋 Testing model listing...")
    models = connector.list_models()
    if models:
        print(f"✅ Found {len(models)} models:")
        for model in models[:3]:  # Show first 3 models
            name = model.get("id", model.get("name", "Unknown"))
            print(f"   - {name}")
    else:
        print("⚠️  No models found or failed to list models")
    
    # Test simple completion
    print("\n💬 Testing chat completion...")
    try:
        test_messages = [{"role": "user", "content": "Say hello in one word."}]
        default_model = os.getenv("MODEL", "dolphin-llama3")
        
        response = connector.chat_completion(
            model=default_model,
            messages=test_messages,
            temperature=0.1,
            max_tokens=10
        )
        
        if "choices" in response and response["choices"]:
            content = response["choices"][0]["message"]["content"]
            print(f"✅ Response: {content}")
        else:
            print("⚠️  Unexpected response format")
            
    except Exception as e:
        print(f"❌ Chat completion test failed: {e}")
    
    print("\n✅ Ollama connector test complete!")


if __name__ == "__main__":
    # Run integration test when executed directly
    test_ollama_connection()
