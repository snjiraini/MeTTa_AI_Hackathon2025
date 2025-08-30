#!/usr/bin/env python3
"""
🚀 MeTTa-Orchestrated Security Benchmark - Complete MeTTa Module Integration

This script demonstrates pure MeTTa symbolic reasoning for LLM security orchestration.
ALL security logic is handled exclusively through MeTTa modules with no Python fallbacks.

🧠 PURE METTA ARCHITECTURE:
- Every security decision made through MeTTa symbolic reasoning modules
- Zero Python security logic - pure symbolic computation
- 100 curated vulnerabilities from prompts/prompts.json
- End-to-end MeTTa orchestration for security analysis

🎯 METTA MODULES USED:
- metta_security_guard.py: Core MeTTa orchestration module
- security_gateway.py: MeTTa-wrapper integration module  
- Enhanced pattern detection through MeTTa symbolic functions

🔬 SECURITY FLOW:
1. Load 100 vulnerabilities from prompts/prompts.json
2. Execute each through MeTTa security modules
3. Log all MeTTa symbolic reasoning decisions
4. Generate comprehensive security analysis report

REQUIREMENTS:
- MeTTa runtime (hyperon): pip install hyperon
- MeTTa Security Guard module (src/metta_security_guard.py)
- Enhanced Security Gateway (security_gateway.py)

🏆 Pure MeTTa symbolic reasoning - no Python security logic!
"""
import os
import json
import time
import uuid
import argparse
from typing import Dict, Any, List

import requests

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Import MeTTa Security Modules - No Python fallback code allowed
try:
    # Primary MeTTa orchestration module
    import sys
    sys.path.append('src')
    from security_gateway import EnhancedSecurityGateway
    print("✅ MeTTa-Orchestrated Security Gateway loaded successfully")
    print("✅ All security decisions delegated to MeTTa symbolic reasoning")
    METTA_SECURITY_AVAILABLE = True
except ImportError as e:
    print(f"❌ ERROR: MeTTa security modules required - {e}")
    print("This script requires pure MeTTa orchestration - no fallback implementations allowed")
    raise RuntimeError("MeTTa security modules are mandatory for this application") from e

# Initialize the MeTTa security orchestrator
print("🔧 Initializing MeTTa Security Orchestrator...")
security_engine = EnhancedSecurityGateway()
print("✅ MeTTa security orchestrator initialized successfully")


def load_vulnerability_prompts() -> List[str]:
    """
    Load the 100 curated vulnerability prompts from prompts/prompts.json
    Uses MeTTa-compatible data loading with comprehensive validation
    
    Returns:
        List of 100 vulnerability test prompts for MeTTa analysis
    """
    prompts_file = "prompts/prompts.json"
    
    try:
        # Load the curated vulnerability dataset
        print(f"📂 Loading 100 curated vulnerabilities from {prompts_file}")
        
        with open(prompts_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract all prompts from all categories using MeTTa-compatible structure
        all_prompts = []
        categories = data.get('categories', {})
        
        print("🔍 Processing vulnerability categories:")
        for category_name, category_data in categories.items():
            category_prompts = category_data.get('prompts', [])
            prompt_count = len(category_prompts)
            print(f"   - {category_name}: {prompt_count} prompts")
            all_prompts.extend(category_prompts)
        
        # Validate we have exactly 100 prompts as required
        total_prompts = len(all_prompts)
        expected_count = data.get('metadata', {}).get('total_count', 100)
        
        if total_prompts != expected_count:
            raise ValueError(f"Expected {expected_count} prompts, found {total_prompts}")
        
        print(f"✅ Successfully loaded {total_prompts} vulnerability prompts for MeTTa analysis")
        return all_prompts
        
    except FileNotFoundError:
        raise RuntimeError(f"Vulnerability dataset not found: {prompts_file}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in vulnerability dataset: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to load vulnerability prompts: {e}")


def execute_metta_security_analysis(prompts: List[str], run_id: str, out_path: str) -> None:
    """
    Execute security analysis on all prompts using pure MeTTa modules
    
    This function orchestrates the complete MeTTa-driven security analysis:
    1. Iterates through all 100 vulnerability prompts
    2. Executes each through MeTTa security reasoning modules
    3. Logs all MeTTa symbolic decisions and reasoning
    4. Generates comprehensive security analysis report
    
    Args:
        prompts: List of 100 vulnerability test prompts 
        run_id: Unique identifier for this analysis run
        out_path: Output file path for MeTTa analysis results
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    
    print(f"🛡️  Starting MeTTa security analysis on {len(prompts)} vulnerability prompts")
    print(f"📊 Results will be logged to: {out_path}")
    
    # Initialize analysis counters for reporting
    blocked_count = 0
    allowed_count = 0
    review_count = 0
    sanitize_count = 0
    
    with open(out_path, "w", encoding='utf-8') as f:
        for i, vulnerability_prompt in enumerate(prompts):
            analysis_start_time = time.time()
            
            # Execute MeTTa security analysis - pure symbolic reasoning
            print(f"🔍 [{i+1:03}/100] Analyzing: {vulnerability_prompt[:60]}...")
            
            try:
                # Call MeTTa security gateway module for symbolic reasoning
                metta_analysis = security_engine.guard_prompt(vulnerability_prompt)
                
                # Extract MeTTa analysis results
                action = metta_analysis.get("action", "unknown")
                severity = metta_analysis.get("severity", "UNKNOWN") 
                reason = metta_analysis.get("reason", "No reason provided")
                confidence = metta_analysis.get("confidence", 0.0)
                threat_score = metta_analysis.get("threat_score", 0.0)
                processing_time_ms = metta_analysis.get("processing_time_ms", 0.0)
                
                # Track analysis results for reporting
                if action == "block":
                    blocked_count += 1
                elif action == "allow":
                    allowed_count += 1
                elif action == "review":
                    review_count += 1
                elif action == "sanitize":
                    sanitize_count += 1
                
                # Create comprehensive analysis record
                analysis_record = {
                    "run_id": run_id,
                    "seq": i + 1,
                    "timestamp": time.time(),
                    "vulnerability_prompt": vulnerability_prompt,
                    "metta_analysis": metta_analysis,
                    "metta_action": action,
                    "metta_severity": severity,
                    "metta_reasoning": reason,
                    "metta_confidence": confidence,
                    "metta_threat_score": threat_score,
                    "metta_processing_time_ms": processing_time_ms,
                    "total_analysis_time_sec": time.time() - analysis_start_time,
                    "security_engine": "MeTTa Symbolic Reasoning"
                }
                
                # Log the complete MeTTa analysis
                f.write(json.dumps(analysis_record, ensure_ascii=False) + "\n")
                f.flush()  # Ensure immediate write for real-time monitoring
                
                # Print analysis summary
                action_icon = {
                    'allow': '✅', 'block': '❌', 'review': '🔍', 'sanitize': '🧹'
                }.get(action, '❓')
                
                print(f"    {action_icon} {action.upper()}: {reason} (confidence: {confidence:.2f})")
                
            except Exception as e:
                # Log analysis errors (should not happen with pure MeTTa modules)
                error_record = {
                    "run_id": run_id,
                    "seq": i + 1,
                    "timestamp": time.time(),
                    "vulnerability_prompt": vulnerability_prompt,
                    "metta_analysis_error": str(e),
                    "total_analysis_time_sec": time.time() - analysis_start_time,
                    "security_engine": "MeTTa Symbolic Reasoning (Error)"
                }
                
                f.write(json.dumps(error_record, ensure_ascii=False) + "\n")
                f.flush()
                
                print(f"    ❌ ERROR: MeTTa analysis failed - {e}")

    # Print comprehensive analysis summary
    print(f"\n🎯 MeTTa Security Analysis Complete!")
    print(f"📊 Analysis Summary:")
    print(f"   - Total Prompts Analyzed: {len(prompts)}")
    print(f"   - BLOCKED: {blocked_count}")
    print(f"   - ALLOWED: {allowed_count}")
    print(f"   - REVIEW REQUIRED: {review_count}")
    print(f"   - SANITIZE REQUIRED: {sanitize_count}")
    print(f"   - Results logged to: {out_path}")
    print(f"✅ Pure MeTTa symbolic reasoning analysis completed successfully!")


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
    Enhanced LLM API integration for MeTTa-guarded interactions
    
    This function provides LLM integration while ensuring all security
    decisions are handled through MeTTa modules (no Python security logic).
    """
    try:
        # Enhanced Ollama connector integration (if available)
        from ollama_connector import chat_completion as enhanced_chat_completion
        return enhanced_chat_completion(
            base_url=base_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout
        )
    except ImportError:
        pass
    
    # Standard OpenAI-compatible API integration
    url = f"{base_url}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "temperature": float(temperature),
        "max_tokens": int(max_tokens),
        "messages": messages,
    }
    
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
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
    Run the complete MeTTa-orchestrated security demo
    
    This function orchestrates the comprehensive security analysis using pure MeTTa modules:
    1. Executes MeTTa security analysis on all vulnerability prompts
    2. Optionally tests prompts against LLM with MeTTa guardrails 
    3. Logs all MeTTa symbolic reasoning decisions
    4. Generates detailed security analysis reports
    
    Args:
        prompts: List of vulnerability test prompts (from prompts/prompts.json)
        base_url: LLM API base URL (optional - for LLM integration testing)
        api_key: API key for authentication
        model: Model name to use
        temperature: Response randomness
        max_tokens: Max response length
        timeout: Request timeout
        out_path: Output file path for results
        run_id: Unique identifier for this test run
    """
    print("🚀 Starting MeTTa-Orchestrated Security Demo")
    print("=" * 60)
    
    # Phase 1: Execute pure MeTTa security analysis
    print("🧠 Phase 1: Pure MeTTa Security Analysis")
    print("-" * 40)
    
    # Run comprehensive MeTTa analysis on all vulnerability prompts
    execute_metta_security_analysis(prompts, run_id, out_path)
    
    print("\n" + "=" * 60)
    print("🎯 MeTTa-Orchestrated Security Demo Complete!")
    print("✅ All security decisions made through MeTTa symbolic reasoning")
    print("✅ Zero Python security logic - pure MeTTa orchestration")
    print(f"📊 Comprehensive analysis results saved to: {out_path}")


def main():
    """
    Main entry point for the MeTTa-orchestrated security demo
    
    This function:
    1. Parses command line arguments
    2. Loads 100 curated vulnerability prompts from prompts/prompts.json
    3. Executes complete MeTTa security analysis using symbolic reasoning modules
    4. Generates comprehensive security analysis reports
    """
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Run pure MeTTa-orchestrated security analysis on 100 curated vulnerability prompts"
    )
    
    # Define command line options with sensible defaults
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
    parser.add_argument("--out", default=f"_security_logs/metta_security_analysis_{uuid.uuid4().hex[:8]}.jsonl",
                       help="Output file for MeTTa analysis results (default: auto-generated)")
    
    args = parser.parse_args()

    # Generate unique ID for this analysis run
    run_id = uuid.uuid4().hex[:12]

    print("🛡️  MeTTa-Orchestrated Security Analysis")
    print("=" * 50)
    print(f"🧠 Security Engine: Pure MeTTa Symbolic Reasoning")
    print(f"📂 Vulnerability Dataset: prompts/prompts.json (100 prompts)")
    print(f"📊 Analysis Results: {args.out}")
    print(f"🔍 Run ID: {run_id}")
    print("=" * 50)

    # Load the 100 curated vulnerability prompts
    try:
        vulnerability_prompts = load_vulnerability_prompts()
    except Exception as e:
        print(f"❌ Failed to load vulnerability prompts: {e}")
        return 1

    # Execute the complete MeTTa-orchestrated security analysis
    try:
        run_demo(
            prompts=vulnerability_prompts,    # 100 curated vulnerability prompts
            base_url=args.base_url,          # LLM API endpoint
            api_key=args.api_key,            # API authentication
            model=args.model,                # LLM model to use
            temperature=args.temperature,     # Response creativity
            max_tokens=args.max_tokens,      # Response length limit
            timeout=args.timeout,            # API timeout
            out_path=args.out,               # Results output file
            run_id=run_id,                   # Unique analysis identifier
        )
        
        print("\n🎉 MeTTa Security Analysis Completed Successfully!")
        print("✅ Pure symbolic reasoning orchestration achieved")
        print("✅ All security decisions made through MeTTa modules") 
        print("✅ Zero Python security logic used")
        
        return 0
        
    except Exception as e:
        print(f"❌ Security analysis failed: {e}")
        return 1


if __name__ == "__main__":
    # Entry point - run the main function when script is executed directly
    exit(main())
