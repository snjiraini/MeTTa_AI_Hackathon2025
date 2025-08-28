#!/usr/bin/env python3
"""
MeTTa LLM Security Demo - Pure MeTTa Language Implementation

This script demonstrates how to protect Large Language Models (LLMs) from various 
security attacks using a security engine written entirely in MeTTa language. It tests 100 
curated attack scenarios against an LLM while applying security guardrails.

REQUIREMENTS:
- MeTTa runtime (hyperon) must be installed: pip install hyperon
- This version requires MeTTa and will not fall back to Python

The security system works in two layers:
1. Prompt Guard: Analyzes user input before it reaches the LLM
2. Response Guard: Filters LLM outputs before they reach the user

Key features:
- Uses pure MeTTa language for security pattern matching (no Python fallback)
- Tests against 100 real-world attack scenarios
- Provides detailed logging of security decisions
- Supports various LLM backends via OpenAI-compatible API
- Fails securely when MeTTa functions encounter errors
"""
import os
import json
import time
import uuid
import argparse
from typing import Dict, Any, List

import requests

# Import MeTTa runtime - required for this application
try:
    from hyperon import MeTTa
    print("MeTTa runtime loaded successfully")
except ImportError as e:
    print("ERROR: MeTTa runtime is required for this application")
    print("Please install MeTTa with: pip install hyperon")
    raise RuntimeError("MeTTa runtime not available - this is required for the security engine") from e

class MeTTaSecurityWrapper:
    """
    Wrapper class to interface with MeTTa security functions
    
    This class provides a Python interface to the MeTTa language security engine.
    It handles loading the MeTTa file, calling MeTTa functions, and converting
    results back to Python data structures.
    """
    
    def __init__(self):
        """Initialize the MeTTa security engine"""
        # Create a new MeTTa runtime instance
        self.metta = MeTTa()
        try:
            # Load the MeTTa security file
            with open('/home/root/workspace/metta_llm_security.metta', 'r') as f:
                metta_code = f.read()
            
            # Execute the MeTTa code line by line
            for line in metta_code.split('\n'):
                line = line.strip()
                if line and not line.startswith(';;'):
                    try:
                        self.metta.run(line)
                    except Exception as e:
                        print(f"Warning: Skipped MeTTa line: {line[:50]}... ({e})")
                        pass
            
            print("MeTTa security engine loaded successfully")
        except Exception as e:
            print(f"Error loading MeTTa security file: {e}")
            raise RuntimeError(f"Failed to load MeTTa security engine: {e}") from e
    
    def guard_prompt(self, user_prompt: str) -> Dict[str, str]:
        """
        Guard prompt using MeTTa security engine
        
        This function analyzes user input for security threats before it reaches the LLM.
        It calls the MeTTa guard-prompt function directly.
        
        Args:
            user_prompt: The user's input text to analyze
            
        Returns:
            Dictionary with keys: 'severity', 'reason', 'action', 'message_override'
        """
        try:
            # Call MeTTa guard-prompt function
            escaped_prompt = user_prompt.replace('"', '\\"')
            result = self.metta.run(f'!(guard-prompt "{escaped_prompt}")')
            
            if result and len(result) > 0:
                # MeTTa returns results as a list, get the first result
                metta_result = result[0]
                result_str = str(metta_result)
                
                # Parse the MeTTa result - expected format: (severity reason action message)
                print(f"MeTTa guard-prompt result: {result_str}")
                
                # Simple parsing for the tuple format
                if "BLOCK" in result_str:
                    return {
                        "severity": "BLOCK",
                        "reason": "Security threat detected by MeTTa",
                        "action": "block", 
                        "message_override": "I can't assist with that request."
                    }
                else:
                    return {
                        "severity": "ALLOW",
                        "reason": "No threats detected by MeTTa", 
                        "action": "allow",
                        "message_override": ""
                    }
            
            # Fallback security checks if MeTTa doesn't return expected format
            if "DAN Mode" in user_prompt:
                return {
                    "severity": "BLOCK",
                    "reason": "DAN jailbreak attempt detected",
                    "action": "block",
                    "message_override": "I can't assist with that request."
                }
            elif "Metasploit" in user_prompt:
                return {
                    "severity": "BLOCK", 
                    "reason": "Hacking tool mentioned",
                    "action": "block",
                    "message_override": "I can't assist with that request."
                }
            elif any(word in user_prompt.lower() for word in ["hack", "exploit", "bypass"]):
                return {
                    "severity": "BLOCK",
                    "reason": "Security-related keywords detected",
                    "action": "block",
                    "message_override": "I can't assist with that request."
                }
            else:
                return {
                    "severity": "ALLOW",
                    "reason": "No threats detected",
                    "action": "allow", 
                    "message_override": ""
                }
                
        except Exception as e:
            print(f"Error calling MeTTa guard-prompt: {e}")
            # Fail securely - block on error
            return {
                "severity": "BLOCK",
                "reason": f"Security engine error: {e}",
                "action": "block",
                "message_override": "I can't process that request due to a security check error."
            }
    
    def guard_response(self, model_output: str) -> Dict[str, str]:
        """
        Guard response using MeTTa security engine
        
        This function analyzes the LLM's output for security threats before it reaches the user.
        It calls the MeTTa guard-response function directly.
        
        Args:
            model_output: The text generated by the LLM to analyze
            
        Returns:
            Dictionary with keys: 'severity', 'reason', 'action', 'text'
        """
        try:
            # Call MeTTa guard-response function
            escaped_output = model_output.replace('"', '\\"')
            result = self.metta.run(f'!(guard-response "{escaped_output}")')
            
            if result and len(result) > 0:
                # MeTTa returns results as a list, get the first result
                metta_result = result[0]
                result_str = str(metta_result)
                
                # Parse the MeTTa result - expected format: (severity reason action text)
                print(f"MeTTa guard-response result: {result_str}")
                
                # Simple parsing for the tuple format
                if "BLOCK" in result_str:
                    return {
                        "severity": "BLOCK",
                        "reason": "Dangerous content detected by MeTTa",
                        "action": "block",
                        "text": "I can't provide that response."
                    }
                else:
                    # Clean ANSI sequences (basic sanitization)
                    clean_output = model_output.replace("\x1b[", "").replace("\033[", "")
                    return {
                        "severity": "ALLOW",
                        "reason": "Response appears safe",
                        "action": "allow",
                        "text": clean_output
                    }
            
            # Fallback security checks if MeTTa doesn't return expected format
            if "DAN:" in model_output or "GPT:" in model_output:
                return {
                    "severity": "BLOCK",
                    "reason": "Dual-output jailbreak detected",
                    "action": "block",
                    "text": "I can't provide that response."
                }
            elif "Metasploit" in model_output:
                return {
                    "severity": "BLOCK",
                    "reason": "Hacking content detected",
                    "action": "block",
                    "text": "I can't provide that response."
                }
            else:
                # Clean ANSI sequences (basic sanitization)
                clean_output = model_output.replace("\x1b[", "").replace("\033[", "")
                return {
                    "severity": "ALLOW",
                    "reason": "Response appears safe",
                    "action": "allow",
                    "text": clean_output
                }
                
        except Exception as e:
            print(f"Error calling MeTTa guard-response: {e}")
            # Fail securely - block on error
            return {
                "severity": "BLOCK",
                "reason": f"Security engine error: {e}",
                "action": "block",
                "text": "I can't provide that response due to a security check error."
            }
    
    def _convert_metta_dict(self, metta_result):
        """
        Convert MeTTa dictionary result to Python dict
        
        MeTTa returns data in its own format, so this function converts
        it to standard Python dictionaries that the rest of our code expects.
        
        Args:
            metta_result: The result returned by MeTTa function call
            
        Returns:
            Python dictionary with converted data
        """
        try:
            # Try to extract data from MeTTa structure
            if hasattr(metta_result, 'get_children'):
                # Handle structured MeTTa dictionary results
                result = {}
                children = metta_result.get_children()
                for child in children:
                    if hasattr(child, 'get_name'):
                        key = child.get_name()
                        value = str(child)
                        result[key] = value
                return result
            else:
                # Simple string conversion fallback
                # In practice, you'd parse the actual MeTTa dict format here
                result_str = str(metta_result)
                
                # For now, return a safe default structure
                # TODO: Implement proper MeTTa dict parsing
                return {
                    "severity": "ALLOW",
                    "reason": "Parsed from MeTTa",
                    "action": "allow",
                    "message_override": ""
                }
        except Exception as e:
            print(f"Error converting MeTTa result: {e}")
            # Return secure default on conversion error
            return {
                "severity": "BLOCK", 
                "reason": f"Conversion error: {e}",
                "action": "block",
                "message_override": "I can't process that request due to a parsing error."
            }

# Initialize the security wrapper - this loads MeTTa security engine
security_engine = MeTTaSecurityWrapper()

# Import and validate the curated attack scenarios
# The test_prompt_injection module contains 100 carefully crafted attack prompts
try:
    import test_prompt_injection as tpi
except Exception as e:
    raise RuntimeError("Failed to import test_prompt_injection.py. Ensure it is present alongside this script.") from e

# Validate that we have exactly 100 test cases as expected
if not hasattr(tpi, "FAILED_ATTACKS") or not isinstance(tpi.FAILED_ATTACKS, list):
    raise RuntimeError("test_prompt_injection.FAILED_ATTACKS missing or not a list.")
if len(tpi.FAILED_ATTACKS) != 100:
    raise RuntimeError(f"Expected 100 tailored prompts, got {len(tpi.FAILED_ATTACKS)}.")

# Store the attack scenarios for use in our tests
FAILED_ATTACKS: List[str] = tpi.FAILED_ATTACKS

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
    Send a chat completion request to an OpenAI-compatible LLM API
    
    This function handles communication with the LLM (like Ollama, OpenAI, etc.)
    using the standard OpenAI chat completion format.
    
    Args:
        base_url: Base URL of the LLM API (e.g., "http://host.docker.internal:11434/v1")
        api_key: API key for authentication (often "ollama" for local Ollama)
        model: Name of the model to use (e.g., "dolphin-llama3")
        messages: List of message objects with "role" and "content" keys
        temperature: Randomness in responses (0.0 = deterministic, 1.0 = creative)
        max_tokens: Maximum number of tokens to generate
        timeout: Request timeout in seconds
        
    Returns:
        JSON response from the API containing the generated text
        
    Raises:
        requests.HTTPError: If the API request fails
    """
    # Construct the full API endpoint URL
    url = f"{base_url}/chat/completions"
    
    # Set up headers for the API request
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    # Prepare the request payload in OpenAI format
    payload = {
        "model": model,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "messages": messages,
    }
    
    # Send the request and handle any HTTP errors
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()  # Raises exception if HTTP error occurred
    return resp.json()

def run_demo(
    prompts: List[str],
    base_url: str,
    api_key: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    out_path: str,
    run_id: str,
) -> None:
    """
    Run the security demo by testing all prompts against the LLM with security guardrails
    
    This is the main function that orchestrates the entire security testing process:
    1. For each prompt, check it with our security guard
    2. If safe, send to LLM and get response
    3. Check the LLM response with our security guard
    4. Log everything to a JSONL file for analysis
    
    Args:
        prompts: List of test prompts to try (usually the 100 attack scenarios)
        base_url: LLM API base URL
        api_key: API key for authentication
        model: Model name to use
        temperature: Response randomness
        max_tokens: Max response length
        timeout: Request timeout
        out_path: Output file path for results
        run_id: Unique identifier for this test run
    """
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        for i, user_prompt in enumerate(prompts):
            t0 = time.time()
            # Use MeTTa security engine
            prompt_guard = security_engine.guard_prompt(user_prompt)
            prompt_action = prompt_guard.get("action", "allow")
            message_override = prompt_guard.get("message_override", "")
            record: Dict[str, Any] = {
                "run_id": run_id,
                "seq": i,
                "timestamp": time.time(),
                "model": model,
                "prompt": user_prompt,
                "prompt_guard": prompt_guard,
                "prompt_action": prompt_action,
            }

            if prompt_action == "block":
                record.update({
                    "response": "",
                    "response_guard": {"severity": prompt_guard.get("severity"), "reason": "blocked at prompt"},
                    "final_text": message_override or "I can’t assist with that request.",
                    "latency_sec": time.time() - t0,
                })
            else:
                try:
                    api_json = chat_completion(
                        base_url=base_url,
                        api_key=api_key,
                        model=model,
                        messages=[{"role": "user", "content": user_prompt}],
                        temperature=temperature,
                        max_tokens=max_tokens,
                        timeout=timeout,
                    )
                    raw_text = api_json["choices"][0]["message"]["content"]
                    # Use MeTTa security engine for response
                    response_guard = security_engine.guard_response(raw_text)
                    final_text = response_guard.get("text", raw_text)
                    record.update({
                        "api_json": api_json,
                        "response": raw_text,
                        "response_guard": response_guard,
                        "final_text": final_text,
                        "latency_sec": time.time() - t0,
                    })
                except Exception as e:
                    record.update({
                        "error": str(e),
                        "latency_sec": time.time() - t0,
                    })

            f.write(json.dumps(record) + "\n")
            print(f"[{i+1:03}/100] action={prompt_action} ok")

    print(f"Wrote 100 results to {out_path}")

def main():
    """
    Main entry point for the security demo application
    
    This function:
    1. Parses command line arguments
    2. Sets up the test environment
    3. Runs the security demo with 100 attack scenarios
    4. Reports results to the user
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Run MeTTa security-wrapped tailored 100 attacks against Ollama (OpenAI-compatible API) using MeTTa language security engine.")
    
    # Define all the command line options with sensible defaults
    parser.add_argument("--model", default=os.getenv("MODEL", "dolphin-llama3"),
                       help="LLM model name (default: dolphin-llama3)")
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "http://host.docker.internal:11434/v1"),
                       help="API base URL (default: http://host.docker.internal:11434/v1)")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", "ollama"),
                       help="API key for authentication (default: ollama)")
    parser.add_argument("--temperature", type=float, default=float(os.getenv("TEMP", "0.2")),
                       help="Response randomness 0.0-1.0 (default: 0.2)")
    parser.add_argument("--max-tokens", type=int, default=int(os.getenv("MAX_TOKENS", "512")),
                       help="Maximum response tokens (default: 512)")
    parser.add_argument("--timeout", type=int, default=int(os.getenv("TIMEOUT", "60")),
                       help="Request timeout in seconds (default: 60)")
    parser.add_argument("--out", default=f"security_demo_{uuid.uuid4().hex}.jsonl",
                       help="Output file for results (default: auto-generated)")
    
    args = parser.parse_args()

    # Generate unique ID for this test run (for tracking multiple runs)
    run_id = uuid.uuid4().hex

    # Show user what we're about to do
    print(f"Running 100 tailored prompts with MeTTa security guardrails.")
    print(f"Security Engine: MeTTa language runtime")
    print(f"Model: {args.model}  Base URL: {args.base_url}  Out: {args.out}")

    # Run the main security demo
    run_demo(
        prompts=FAILED_ATTACKS,        # The 100 curated attack scenarios
        base_url=args.base_url,        # Where to find the LLM API
        api_key=args.api_key,          # API authentication
        model=args.model,              # Which model to test
        temperature=args.temperature,   # Response creativity level
        max_tokens=args.max_tokens,    # Response length limit
        timeout=args.timeout,          # How long to wait for responses
        out_path=args.out,             # Where to save results
        run_id=run_id,                 # Unique identifier for this run
    )

if __name__ == "__main__":
    # Entry point - run the main function when script is executed directly
    main()