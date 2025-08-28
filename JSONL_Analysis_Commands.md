# JSONL Analysis Commands

This document contains the commands used to read and analyze the security demo output files.

## File Listing Commands

### List all JSONL output files
```bash
ls -la security_demo_*.jsonl
```

### Get the most recent JSONL file
```bash
ls -la security_demo_*.jsonl | tail -1
```

## JSON Analysis Commands

### Using jq (if available)
```bash
# Extract specific fields from JSONL entries
head -3 security_demo_*.jsonl | tail -1 | jq -c '{seq: .seq, prompt: .prompt[:50], prompt_action: .prompt_action, final_text: .final_text[:100]}'

# Pretty print a single JSONL entry
head -1 security_demo_*.jsonl | jq '.'

# Extract all prompt actions
cat security_demo_*.jsonl | jq -r '.prompt_action'

# Count blocked vs allowed actions
cat security_demo_*.jsonl | jq -r '.prompt_action' | sort | uniq -c
```

### Using Python (when jq is not available)

#### Basic analysis of first few entries
```python
import json

# Read and display first 3 test results
with open('security_demo_ae9f5ed209134de9833038ac124aadde.jsonl', 'r') as f:
    for i, line in enumerate(f):
        if i < 3:
            data = json.loads(line)
            print(f'Test {data["seq"]}: {data["prompt"][:60]}... -> Action: {data["prompt_action"]}')
        if i >= 2:
            break
```

#### Count security actions
```python
import json
from collections import Counter

actions = []
with open('security_demo_*.jsonl', 'r') as f:
    for line in f:
        data = json.loads(line)
        actions.append(data['prompt_action'])

counter = Counter(actions)
print("Security Actions:", counter)
```

#### Extract blocked prompts
```python
import json

blocked_prompts = []
with open('security_demo_*.jsonl', 'r') as f:
    for line in f:
        data = json.loads(line)
        if data['prompt_action'] == 'block':
            blocked_prompts.append({
                'seq': data['seq'],
                'prompt': data['prompt'][:100] + '...',
                'reason': data['prompt_guard']['reason']
            })

for prompt in blocked_prompts:
    print(f"Blocked #{prompt['seq']}: {prompt['prompt']}")
    print(f"Reason: {prompt['reason']}\n")
```

#### Analyze response patterns
```python
import json

responses = []
with open('security_demo_*.jsonl', 'r') as f:
    for line in f:
        data = json.loads(line)
        if 'response' in data and data['response']:
            responses.append({
                'seq': data['seq'],
                'response_length': len(data['response']),
                'contains_harmful': any(word in data['response'].lower() 
                                      for word in ['hack', 'exploit', 'malicious', 'attack'])
            })

harmful_responses = [r for r in responses if r['contains_harmful']]
print(f"Found {len(harmful_responses)} potentially harmful responses out of {len(responses)} total")
```

## Terminal Output Analysis

### Show last 20 lines of demo execution
```bash
python run_security_demo.py --timeout 5 --max-tokens 30 2>/dev/null | tail -20
```

### Extract specific patterns from output
```bash
# Find all blocked actions
grep "action=block" security_demo_output.log

# Count total processed
grep -c "action=" security_demo_output.log
```

## File Operations

### Check file size and basic info
```bash
wc -l security_demo_*.jsonl  # Count lines
du -h security_demo_*.jsonl  # Check file size
file security_demo_*.jsonl   # Check file type
```

### Backup important results
```bash
cp security_demo_*.jsonl results_backup/
```

## Complete Analysis Script Example

```python
#!/usr/bin/env python3
"""
Complete JSONL Security Demo Analysis
"""
import json
import glob
from collections import Counter, defaultdict

def analyze_security_demo(filename):
    """Comprehensive analysis of security demo results"""
    
    results = {
        'total_tests': 0,
        'actions': Counter(),
        'blocked_prompts': [],
        'response_analysis': defaultdict(int),
        'error_count': 0
    }
    
    with open(filename, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                results['total_tests'] += 1
                results['actions'][data['prompt_action']] += 1
                
                if data['prompt_action'] == 'block':
                    results['blocked_prompts'].append({
                        'seq': data['seq'],
                        'prompt': data['prompt'][:100],
                        'reason': data.get('prompt_guard', {}).get('reason', 'Unknown')
                    })
                
                if 'response' in data:
                    response = data['response'].lower()
                    if any(word in response for word in ['hack', 'exploit', 'malicious']):
                        results['response_analysis']['potentially_harmful'] += 1
                    if 'error' in response or 'sorry' in response:
                        results['response_analysis']['refused'] += 1
                        
            except json.JSONDecodeError as e:
                results['error_count'] += 1
                print(f"JSON decode error on line: {e}")
    
    return results

# Usage
if __name__ == "__main__":
    files = glob.glob('security_demo_*.jsonl')
    if files:
        latest_file = max(files)
        results = analyze_security_demo(latest_file)
        
        print(f"Analysis of {latest_file}")
        print(f"Total tests: {results['total_tests']}")
        print(f"Actions: {dict(results['actions'])}")
        print(f"Blocked prompts: {len(results['blocked_prompts'])}")
        print(f"Response analysis: {dict(results['response_analysis'])}")
```

## Notes

- Replace `security_demo_*.jsonl` with the actual filename when using specific file commands
- The JSONL format contains one JSON object per line
- Each entry represents one test case from the security demo
- Key fields include: `seq`, `prompt`, `prompt_action`, `response`, `final_text`, `prompt_guard`, `response_guard`
- Actions can be: `allow`, `block`, `soft_block`, etc.
- Use `2>/dev/null` to suppress stderr output when needed
