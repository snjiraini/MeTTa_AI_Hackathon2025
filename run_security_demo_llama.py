#!/usr/bin/env python3
"""
🚀 LLaMA Response Security Guard - MeTTa-Orchestrated Response Analysis

This script demonstrates MeTTa-orchestrated security analysis of LLaMA model responses.
It sends vulnerability prompts to LLaMA and then analyzes the model's responses using
pure MeTTa symbolic reasoning to determine if they should be allowed or blocked.

🧠 ARCHITECTURE:
1. Load vulnerability prompts from prompts/prompts.json
2. Send each prompt to LLaMA model via Ollama API  
3. Analyze LLaMA's response (not original prompt) using MeTTa security guard
4. Make allow/block decisions based on MeTTa symbolic reasoning
5. Log comprehensive analysis results

🔬 SECURITY FLOW:
User Prompt → LLaMA Model → Model Response → MeTTa Security Guard → Action

REQUIREMENTS:
- LLaMA model running via Ollama (configured in .env)
- MeTTa runtime (hyperon): pip install hyperon
- MeTTa Security Guard module (src/metta_security_guard.py)
- Environment variables in .env file

🏆 Pure MeTTa symbolic reasoning for response filtering!
"""

import os
import json
import time
import uuid
import argparse
from typing import Dict, Any, List, Optional
from pathlib import Path

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Environment variables loaded from .env")
except ImportError:
    print("⚠️  python-dotenv not available, using system environment")
    pass

# Import MeTTa Security Modules
try:
    import sys
    import os
    
    # Add src directory to path for package imports
    current_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(current_dir, 'src')
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
    
    # Import src as a package to enable relative imports
    import src
    from metta_security_guard import MeTTaSecurityGuard
    from src.core_types import SecurityContext
    
    print("✅ MeTTa Security Guard loaded successfully")
    METTA_AVAILABLE = True
except ImportError as e:
    print(f"❌ ERROR: MeTTa security modules required - {e}")
    raise RuntimeError("MeTTa security modules are mandatory for this application") from e

# Import LLaMA connector
try:
    from ollama_connector import chat_completion
    print("✅ Ollama connector loaded successfully")
    OLLAMA_AVAILABLE = True
except ImportError as e:
    print(f"❌ ERROR: Ollama connector required - {e}")
    raise RuntimeError("Ollama connector is mandatory for LLaMA integration") from e


def load_vulnerability_prompts() -> List[str]:
    """
    Load vulnerability prompts from prompts/prompts.json
    
    Returns:
        List of vulnerability test prompts
    """
    prompts_file = "prompts/prompts.json"
    
    try:
        print(f"📂 Loading vulnerability prompts from {prompts_file}")
        
        with open(prompts_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract all prompts from all categories
        all_prompts = []
        categories = data.get('categories', {})
        
        print("🔍 Processing vulnerability categories:")
        for category_name, category_data in categories.items():
            category_prompts = category_data.get('prompts', [])
            prompt_count = len(category_prompts)
            print(f"   - {category_name}: {prompt_count} prompts")
            all_prompts.extend(category_prompts)
        
        total_prompts = len(all_prompts)
        print(f"✅ Successfully loaded {total_prompts} vulnerability prompts")
        return all_prompts
        
    except FileNotFoundError:
        raise RuntimeError(f"Vulnerability dataset not found: {prompts_file}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in vulnerability dataset: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to load vulnerability prompts: {e}")


def query_llama_model(
    prompt: str,
    base_url: str,
    api_key: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int
) -> Dict[str, Any]:
    """
    Send prompt to LLaMA model and get response
    
    Args:
        prompt: User prompt to send to model
        base_url: Ollama API base URL
        api_key: API key for authentication
        model: Model name to use
        temperature: Response randomness
        max_tokens: Maximum response tokens
        timeout: Request timeout
        
    Returns:
        Dictionary containing model response and metadata
    """
    try:
        messages = [{"role": "user", "content": prompt}]
        
        start_time = time.time()
        response = chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout
        )
        response_time = time.time() - start_time
        
        # Extract model response content
        model_response = ""
        if "choices" in response and len(response["choices"]) > 0:
            model_response = response["choices"][0].get("message", {}).get("content", "")
        
        return {
            "success": True,
            "model_response": model_response,
            "response_time_sec": response_time,
            "full_response": response,
            "error": None
        }
        
    except Exception as e:
        return {
            "success": False,
            "model_response": "",
            "response_time_sec": 0.0,
            "full_response": None,
            "error": str(e)
        }


def analyze_model_response_with_metta(response_text: str, security_guard: MeTTaSecurityGuard) -> Dict[str, Any]:
    """
    Analyze LLaMA model response using MeTTa security guard
    
    Args:
        response_text: Model response to analyze
        security_guard: MeTTa security guard instance
        
    Returns:
        Dictionary containing security analysis results
    """
    try:
        # Create security context for model response analysis
        context = SecurityContext(
            usage_context="model_response",
            metadata={"analysis_type": "llama_response_guard"}
        )
        
        # Analyze model response using MeTTa symbolic reasoning
        start_time = time.time()
        security_result = security_guard.guard_response(response_text, context=context)
        analysis_time = time.time() - start_time
        
        # Convert MeTTa result to action
        decision = security_result.decision.value.lower()  # allow, block, review, sanitize
        action = "allow" if decision in ["allow"] else "block"  # Simplified to allow/block
        
        return {
            "success": True,
            "metta_decision": decision,
            "action": action,
            "confidence": security_result.confidence,
            "threat_score": security_result.threat_score,
            "reasoning": security_result.reasoning_chain[0].conclusion if security_result.reasoning_chain else "No reasoning provided",
            "matched_patterns": [pm.match_text for pm in security_result.matched_patterns],
            "analysis_time_sec": analysis_time,
            "processing_time_ms": security_result.processing_time_ms,
            "metadata": security_result.metadata,
            "error": None
        }
        
    except Exception as e:
        # Fail-secure: block on error
        return {
            "success": False,
            "metta_decision": "block",
            "action": "block",
            "confidence": 1.0,
            "threat_score": 1.0,
            "reasoning": f"Analysis failed: {str(e)}",
            "matched_patterns": [],
            "analysis_time_sec": 0.0,
            "processing_time_ms": 0.0,
            "metadata": {"error": str(e)},
            "error": str(e)
        }


def execute_llama_response_analysis(
    prompts: List[str],
    base_url: str,
    api_key: str,
    model: str,
    temperature: float,
    max_tokens: int,
    timeout: int,
    out_path: str,
    run_id: str
) -> None:
    """
    Execute complete LLaMA response analysis pipeline
    
    Args:
        prompts: List of vulnerability prompts to test
        base_url: Ollama API base URL
        api_key: API key for authentication
        model: Model name to use
        temperature: Response randomness
        max_tokens: Maximum response tokens
        timeout: Request timeout
        out_path: Output file path for results
        run_id: Unique identifier for this run
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    
    # Initialize MeTTa security guard
    print("🔧 Initializing MeTTa Security Guard for response analysis...")
    security_guard = MeTTaSecurityGuard()
    print("✅ MeTTa Security Guard initialized successfully")
    
    print(f"🛡️  Starting LLaMA response security analysis on {len(prompts)} prompts")
    print(f"📊 Results will be logged to: {out_path}")
    
    # Initialize counters
    allowed_count = 0
    blocked_count = 0
    model_errors = 0
    guard_errors = 0
    
    with open(out_path, "w", encoding='utf-8') as f:
        for i, prompt in enumerate(prompts):
            print(f"🔍 [{i+1:03}/{len(prompts)}] Processing: {prompt[:60]}...")
            
            analysis_start_time = time.time()
            
            # Step 1: Send prompt to LLaMA model
            llama_result = query_llama_model(
                prompt=prompt,
                base_url=base_url,
                api_key=api_key,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout
            )
            
            if not llama_result["success"]:
                model_errors += 1
                print(f"    ❌ Model query failed: {llama_result['error']}")
                
                # Log the error
                error_record = {
                    "run_id": run_id,
                    "seq": i + 1,
                    "timestamp": time.time(),
                    "user_prompt": prompt,
                    "llama_response": "",
                    "llama_error": llama_result["error"],
                    "metta_analysis": {"action": "block", "reasoning": "Model query failed"},
                    "final_action": "block",
                    "total_time_sec": time.time() - analysis_start_time
                }
                f.write(json.dumps(error_record, ensure_ascii=False) + "\n")
                f.flush()
                blocked_count += 1
                continue
            
            model_response = llama_result["model_response"]
            print(f"    🤖 LLaMA response: {model_response[:50]}...")
            
            # Step 2: Analyze model response with MeTTa security guard
            metta_result = analyze_model_response_with_metta(model_response, security_guard)
            
            if not metta_result["success"]:
                guard_errors += 1
                print(f"    ❌ MeTTa analysis failed: {metta_result['error']}")
            
            # Step 3: Take action based on MeTTa decision
            final_action = metta_result["action"]
            if final_action == "allow":
                allowed_count += 1
                action_icon = "✅"
            else:
                blocked_count += 1
                action_icon = "❌"
                
            print(f"    {action_icon} {final_action.upper()}: {metta_result['reasoning']} (confidence: {metta_result['confidence']:.2f})")
            
            # Create comprehensive analysis record
            analysis_record = {
                "run_id": run_id,
                "seq": i + 1,
                "timestamp": time.time(),
                "user_prompt": prompt,
                "llama_response": model_response,
                "llama_response_time_sec": llama_result["response_time_sec"],
                "metta_analysis": {
                    "decision": metta_result["metta_decision"],
                    "confidence": metta_result["confidence"],
                    "threat_score": metta_result["threat_score"],
                    "reasoning": metta_result["reasoning"],
                    "matched_patterns": metta_result["matched_patterns"],
                    "processing_time_ms": metta_result["processing_time_ms"]
                },
                "final_action": final_action,
                "total_time_sec": time.time() - analysis_start_time,
                "metadata": {
                    "model": model,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                }
            }
            
            # Log the complete analysis
            f.write(json.dumps(analysis_record, ensure_ascii=False) + "\n")
            f.flush()  # Ensure immediate write
    
    # Print comprehensive summary
    print(f"\n🎯 LLaMA Response Security Analysis Complete!")
    print(f"📊 Analysis Summary:")
    print(f"   - Total Prompts: {len(prompts)}")
    print(f"   - Model Responses ALLOWED: {allowed_count}")
    print(f"   - Model Responses BLOCKED: {blocked_count}")
    print(f"   - Model Query Errors: {model_errors}")
    print(f"   - MeTTa Analysis Errors: {guard_errors}")
    print(f"   - Results logged to: {out_path}")
    print(f"✅ LLaMA response security analysis completed successfully!")


def main():
    """
    Main entry point for LLaMA response security analysis
    """
    parser = argparse.ArgumentParser(
        description="Analyze LLaMA model responses using MeTTa security guard"
    )
    
    # Command line arguments with defaults from environment
    parser.add_argument("--model", default=os.getenv("MODEL", "dolphin-llama3"),
                       help="LLaMA model name")
    parser.add_argument("--base-url", default=os.getenv("OPENAI_BASE_URL", "http://host.docker.internal:11434/v1"),
                       help="Ollama API base URL")
    parser.add_argument("--api-key", default=os.getenv("OPENAI_API_KEY", "ollama"),
                       help="API key for authentication")
    parser.add_argument("--temperature", type=float, default=float(os.getenv("TEMP", "0.2")),
                       help="Response randomness 0.0-1.0")
    parser.add_argument("--max-tokens", type=int, default=int(os.getenv("MAX_TOKENS", "512")),
                       help="Maximum response tokens")
    parser.add_argument("--timeout", type=int, default=int(os.getenv("TIMEOUT", "60")),
                       help="Request timeout in seconds")
    parser.add_argument("--out", default=f"_security_logs/llama_response_analysis_{uuid.uuid4().hex[:8]}.jsonl",
                       help="Output file for analysis results")
    parser.add_argument("--max-prompts", type=int, default=10,
                       help="Maximum number of prompts to process (for testing)")
    
    args = parser.parse_args()
    
    # Generate unique run ID
    run_id = uuid.uuid4().hex[:12]
    
    print("🦙 LLaMA Response Security Analysis")
    print("=" * 50)
    print(f"🤖 Model: {args.model}")
    print(f"🔗 API URL: {args.base_url}")
    print(f"🧠 Security Engine: MeTTa Symbolic Reasoning")
    print(f"📊 Results: {args.out}")
    print(f"🔍 Run ID: {run_id}")
    print("=" * 50)
    
    try:
        # Load vulnerability prompts
        all_prompts = load_vulnerability_prompts()
        
        # Limit prompts for testing if requested
        if args.max_prompts and args.max_prompts < len(all_prompts):
            prompts = all_prompts[:args.max_prompts]
            print(f"📝 Using first {args.max_prompts} prompts for testing")
        else:
            prompts = all_prompts
            
        # Execute analysis
        execute_llama_response_analysis(
            prompts=prompts,
            base_url=args.base_url,
            api_key=args.api_key,
            model=args.model,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
            out_path=args.out,
            run_id=run_id
        )
        
        print("\n🎉 LLaMA Response Analysis Completed Successfully!")
        print("✅ Model responses analyzed through MeTTa symbolic reasoning")
        print("✅ Allow/block actions taken based on security analysis")
        
        return 0
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
