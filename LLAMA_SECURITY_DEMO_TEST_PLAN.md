# Manual Test Plan for run_security_demo_llama.py

## Overview
This document provides a comprehensive manual test plan for the LLaMA response security analysis script. The script sends vulnerability prompts to LLaMA and analyzes the model's responses using MeTTa symbolic reasoning.

## Test Environment Setup

### Prerequisites
1. **Ollama Running**: Ensure Ollama is running with LLaMA model
2. **Environment File**: Ensure `.env` file is configured
3. **Dependencies**: Install required Python packages
4. **MeTTa Runtime**: Ensure MeTTa symbolic reasoning is available

### Environment Configuration Check
```bash
# Verify .env file exists and contains required variables
cat .env

# Expected variables:
# OPENAI_API_KEY=ollama
# OPENAI_BASE_URL=http://host.docker.internal:11434/v1
# MODEL=dolphin-llama3
# TEMP=0.2
# MAX_TOKENS=512
# TIMEOUT=60
```

## Test Plan Structure

### Phase 1: Basic Functionality Tests

#### Test 1.1: Script Initialization
**Objective**: Verify script loads successfully with all dependencies

**Steps**:
1. Run the script with help flag
```bash
python run_security_demo_llama.py --help
```

**Expected Result**:
- Script displays help message with all available options
- No import errors or missing dependencies

**Pass Criteria**: ✅ Help message displays without errors

---

#### Test 1.2: Environment Variable Loading
**Objective**: Verify environment variables are loaded correctly

**Steps**:
1. Run script with verbose output to see environment loading
```bash
python run_security_demo_llama.py --max-prompts 1
```

**Expected Result**:
- ✅ Environment variables loaded from .env
- ✅ MeTTa Security Guard loaded successfully  
- ✅ Ollama connector loaded successfully

**Pass Criteria**: All three success messages appear

---

#### Test 1.3: Vulnerability Prompts Loading
**Objective**: Verify prompts are loaded from prompts/prompts.json

**Steps**:
1. Check prompts file exists
```bash
ls -la prompts/prompts.json
```

2. Run script with limited prompts
```bash
python run_security_demo_llama.py --max-prompts 3
```

**Expected Result**:
- ✅ Successfully loaded X vulnerability prompts
- Processing vulnerability categories listed
- Script processes exactly 3 prompts

**Pass Criteria**: Prompts loaded and categories displayed

---

### Phase 2: LLaMA Integration Tests

#### Test 2.1: LLaMA Connection Test
**Objective**: Verify connection to LLaMA model via Ollama

**Prerequisites**: Ollama must be running with the specified model

**Steps**:
1. Test with single safe prompt
```bash
python run_security_demo_llama.py --max-prompts 1 --out test_output.jsonl
```

2. Check if LLaMA responds
```bash
cat test_output.jsonl | head -1 | jq '.llama_response'
```

**Expected Result**:
- 🔍 [001/001] Processing: [prompt preview]
- 🤖 LLaMA response: [response preview]
- No model query errors

**Pass Criteria**: LLaMA response is received and not empty

---

#### Test 2.2: LLaMA Error Handling
**Objective**: Test handling of LLaMA connection failures

**Steps**:
1. Stop Ollama service temporarily or use invalid URL
```bash
python run_security_demo_llama.py --base-url http://invalid:11434/v1 --max-prompts 1
```

**Expected Result**:
- ❌ Model query failed: [error message]
- Model Responses BLOCKED: 1 (fail-secure behavior)
- Model Query Errors: 1

**Pass Criteria**: Script handles errors gracefully and blocks on failure

---

### Phase 3: MeTTa Security Analysis Tests

#### Test 3.1: Safe Content Analysis  
**Objective**: Verify MeTTa correctly identifies safe responses

**Steps**:
1. Use prompts likely to generate safe responses
```bash
python run_security_demo_llama.py --max-prompts 5 --out safe_test.jsonl
```

2. Check for allowed responses
```bash
grep '"final_action": "allow"' safe_test.jsonl | wc -l
```

**Expected Result**:
- Some responses marked as ✅ ALLOW
- MeTTa reasoning indicates safe content
- Confidence scores appropriate for safe content

**Pass Criteria**: At least some safe responses are allowed

---

#### Test 3.2: Dangerous Content Analysis
**Objective**: Verify MeTTa correctly identifies dangerous responses

**Steps**:
1. Focus on jailbreak/harmful prompts that might generate risky responses
```bash
# Filter to potentially dangerous prompts and test
python run_security_demo_llama.py --max-prompts 10 --out danger_test.jsonl
```

2. Check for blocked responses
```bash
grep '"final_action": "block"' danger_test.jsonl | wc -l
```

**Expected Result**:
- Some responses marked as ❌ BLOCK
- MeTTa reasoning indicates threat detection
- Higher confidence scores for blocked content

**Pass Criteria**: Dangerous content is identified and blocked

---

#### Test 3.3: MeTTa Error Handling
**Objective**: Test MeTTa analysis error handling

**Steps**:
1. This is harder to test manually, but check logs for any MeTTa errors
```bash
python run_security_demo_llama.py --max-prompts 5 --out error_test.jsonl
grep "MeTTa analysis failed" error_test.jsonl
```

**Expected Result**:
- If MeTTa errors occur, they are logged properly
- Fail-secure behavior: errors result in BLOCK action
- Error count reported in summary

**Pass Criteria**: MeTTa errors handled gracefully with fail-secure behavior

---

### Phase 4: Output and Logging Tests

#### Test 4.1: Output File Generation
**Objective**: Verify comprehensive logging to JSONL file

**Steps**:
1. Run full analysis
```bash
python run_security_demo_llama.py --max-prompts 5 --out full_test.jsonl
```

2. Validate output structure
```bash
# Check each record has required fields
head -1 full_test.jsonl | jq 'keys'
```

**Expected Result**:
- JSONL file created in _security_logs/ directory
- Each record contains: run_id, seq, timestamp, user_prompt, llama_response, metta_analysis, final_action
- File is valid JSON Line format

**Pass Criteria**: Output file is properly structured and complete

---

#### Test 4.2: Real-time Logging
**Objective**: Verify real-time progress logging

**Steps**:
1. Run with moderate number of prompts and observe output
```bash
python run_security_demo_llama.py --max-prompts 10
```

**Expected Result**:
- Progress counter: [001/010], [002/010], etc.
- Real-time action feedback: ✅ ALLOW, ❌ BLOCK
- Processing time shown for each prompt
- Final summary statistics

**Pass Criteria**: Real-time feedback is clear and informative

---

### Phase 5: Performance and Edge Cases

#### Test 5.1: Performance with Many Prompts
**Objective**: Test performance with larger datasets

**Steps**:
1. Run with maximum prompts (or large subset)
```bash
time python run_security_demo_llama.py --max-prompts 25 --out performance_test.jsonl
```

2. Check timing and memory usage
```bash
# Analyze timing data from output
cat performance_test.jsonl | jq '.total_time_sec' | awk '{sum+=$1; count++} END {print "Avg time:", sum/count}'
```

**Expected Result**:
- Script completes without memory issues
- Reasonable processing times per prompt
- All prompts processed successfully

**Pass Criteria**: Script handles larger datasets efficiently

---

#### Test 5.2: Edge Case Inputs
**Objective**: Test handling of unusual inputs

**Steps**:
1. Test with empty prompts file or corrupted JSON
```bash
# Backup original and create test case
cp prompts/prompts.json prompts/prompts.json.bak
echo "invalid json" > prompts/prompts.json
python run_security_demo_llama.py --max-prompts 1
# Restore original
mv prompts/prompts.json.bak prompts/prompts.json
```

**Expected Result**:
- ❌ Analysis failed: Invalid JSON in vulnerability dataset
- Script exits with error code 1
- No crash or undefined behavior

**Pass Criteria**: Edge cases handled gracefully with proper error messages

---

## Test Execution Checklist

### Pre-Test Setup
- [ ] Ollama service is running
- [ ] LLaMA model is available (check with `ollama list`)
- [ ] `.env` file is configured correctly
- [ ] `prompts/prompts.json` exists and is valid
- [ ] MeTTa dependencies are installed
- [ ] Output directory `_security_logs/` exists or can be created

### Test Execution
- [ ] Test 1.1: Script Initialization
- [ ] Test 1.2: Environment Variable Loading
- [ ] Test 1.3: Vulnerability Prompts Loading
- [ ] Test 2.1: LLaMA Connection Test
- [ ] Test 2.2: LLaMA Error Handling
- [ ] Test 3.1: Safe Content Analysis
- [ ] Test 3.2: Dangerous Content Analysis
- [ ] Test 3.3: MeTTa Error Handling
- [ ] Test 4.1: Output File Generation
- [ ] Test 4.2: Real-time Logging
- [ ] Test 5.1: Performance with Many Prompts
- [ ] Test 5.2: Edge Case Inputs

### Post-Test Validation
- [ ] All output files are valid JSONL format
- [ ] No memory leaks or performance issues
- [ ] Error handling works as expected
- [ ] Allow/block decisions are reasonable
- [ ] MeTTa security analysis functions correctly

## Expected Results Summary

### Success Metrics
- **Model Integration**: LLaMA responds to prompts successfully
- **Security Analysis**: MeTTa provides meaningful allow/block decisions
- **Error Handling**: Graceful degradation on failures
- **Performance**: Reasonable processing times
- **Output Quality**: Well-structured logs with complete information

### Failure Indicators
- Script crashes or hangs
- All responses are allowed (no security filtering)
- All responses are blocked (over-aggressive filtering)
- Empty or malformed output files
- Missing error handling

## Troubleshooting Guide

### Common Issues
1. **"MeTTa security modules required"**: Install hyperon package
2. **"Ollama connector required"**: Check ollama_connector.py exists
3. **Connection refused**: Verify Ollama is running and URL is correct
4. **Model not found**: Check model is downloaded in Ollama
5. **Permission denied**: Check write permissions for output directory

### Debug Commands
```bash
# Check Ollama status
curl http://host.docker.internal:11434/api/tags

# Test direct model query
curl http://host.docker.internal:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"dolphin-llama3","messages":[{"role":"user","content":"Hello"}]}'

# Validate output format
cat output.jsonl | jq '.' > /dev/null && echo "Valid JSON" || echo "Invalid JSON"
```

## Test Report Template

```
# LLaMA Security Demo Test Report

**Test Date**: [Date]
**Tester**: [Name]
**Environment**: [OS, Python version, etc.]

## Test Results Summary
- **Tests Passed**: X/12
- **Tests Failed**: X/12
- **Critical Issues**: [List]
- **Minor Issues**: [List]

## Detailed Results
[For each test, mark PASS/FAIL and add notes]

## Recommendations
[Any recommendations for improvements]
```

## Automation Integration

This manual test plan can be supplemented with the automated tests:

```bash
# Run automated unit tests first
python test_llama_security_demo.py

# Then run manual integration tests
python run_security_demo_llama.py --max-prompts 5
```

The combination of automated and manual testing provides comprehensive coverage of the LLaMA response security analysis functionality.
