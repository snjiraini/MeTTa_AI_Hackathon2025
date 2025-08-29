#!/usr/bin/env python3

import sys
sys.path.append('/home/root/workspace/src')

from hyperon import MeTTa
import os
from pathlib import Path

# Test MeTTa execution directly
print("🔍 Testing MeTTa execution directly...")

# Initialize MeTTa
metta = MeTTa()
print("✅ MeTTa initialized")

# Load knowledge base
kb_path = Path(__file__).parent / "src" / "metta_working_final.metta"
print(f"📁 Loading knowledge base from: {kb_path}")

try:
    with open(kb_path, 'r') as f:
        content = f.read()
        print(f"📄 Knowledge base content length: {len(content)} chars")
        print(f"📄 First 200 chars: {content[:200]}")
        
    # Load the module  
    metta.load_module_at_path(str(kb_path))
    print("✅ Knowledge base loaded")
    
    # Try loading functions directly
    print("\n🔍 Adding functions directly...")
    metta.run('(= (health-check) healthy)')
    metta.run('(= (should-block-request "hello" "test") (ALLOW 0.9 "Safe greeting"))')
    metta.run('(= (should-block-request "bomb" "test") (BLOCK 0.9 "Dangerous content"))')
    metta.run('(= (should-block-request $input $context) (ALLOW 0.5 "Default safe response"))')
    print("✅ Functions added directly")    # Test health check
    print("\n🔍 Testing health-check...")
    result = metta.run("! (health-check)")
    print(f"Health check result: {result}")
    
    # Test specific security queries  
    print("\n🔍 Testing hello query...")
    result = metta.run('! (should-block-request "hello" "test")')
    print(f"Hello result: {result}")
    
    print("\n🔍 Testing bomb query...")
    result = metta.run('! (should-block-request "bomb" "test")')
    print(f"Bomb result: {result}")
    
    print("\n🔍 Testing unknown query...")
    result = metta.run('! (should-block-request "unknown" "test")')
    print(f"Unknown result: {result}")
    
    # Extract values from results
    if result:
        for i, item in enumerate(result):
            print(f"  Result[{i}]: {item} (type: {type(item)})")
            if isinstance(item, list) and len(item) >= 3:
                print(f"    Decision: {item[0]}")
                print(f"    Confidence: {item[1]}")
                print(f"    Reasoning: {item[2]}")

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
