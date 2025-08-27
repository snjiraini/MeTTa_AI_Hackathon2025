# MeTTa LLM Security Guard 🛡️

A comprehensive security framework for protecting Large Language Models (LLMs) against prompt injection attacks, built with MeTTa-inspired symbolic reasoning capabilities.

## 🚀 What This Project Does

This project provides a **layered defense system** against LLM prompt injection attacks - one of the biggest security threats to AI systems according to OWASP's Top 10 for LLM security risks.

Think of it as a **smart firewall** for your AI models that:
- ✅ Detects malicious prompts before they reach your LLM
- ✅ Sanitizes harmful outputs from the LLM 
- ✅ Provides explainable security decisions
- ✅ Tests your defenses with 100 curated attack scenarios

## 📁 Project Structure

```
├── metta_llm_security.py      # Core security engine with pattern matching rules
├── test_prompt_injection.py   # 100 curated attack scenarios for testing
├── run_security_demo.py       # Complete demo with security guardrails
├── analyze_garak_hits.py      # Analysis tool for security test results
├── 1_run_garak.ipynb          # Jupyter notebook for interactive testing
└── docs/
    ├── product_justification.md # Technical background on prompt injection
    └── important links.txt      # Useful security resources
```

## 🏃‍♀️ Quick Start

### Prerequisites
- Python 3.8+
- Local LLM server (like Ollama) running on `http://localhost:11434`
- Required packages: `requests`

### 1. Install Dependencies
```bash
pip install requests
```

### 2. Start Your Local LLM (Optional)
If using Ollama:
```bash
# Install Ollama first, then:
ollama serve
ollama pull dolphin-llama3  # or your preferred model
```

### 3. Test the Security Engine
```bash
# Run the core security engine with example attacks
python metta_llm_security.py
```

### 4. Run Full Security Demo
```bash
# Test 100 attack scenarios with security guardrails
python run_security_demo.py --model dolphin-llama3
```

### 5. Analyze Results
```bash
# View which attacks were blocked vs allowed
python analyze_garak_hits.py results.jsonl
```

## 🔍 How It Works

### Security Layers

1. **Prompt Guard** - Analyzes incoming prompts and blocks/sanitizes dangerous ones
2. **Response Guard** - Filters model outputs to prevent harmful content from reaching users
3. **Pattern Detection** - Uses regex patterns to identify known attack vectors

### Attack Categories Detected

| Category | Examples | Action |
|----------|----------|---------|
| **Jailbreaks** | "DAN Mode", "Ignore previous instructions" | 🚫 BLOCK |
| **Harmful Instructions** | Hacking guides, bomb-making | 🚫 BLOCK |  
| **Control Sequences** | ANSI escape codes, terminal injection | 🧹 SANITIZE |
| **Toxic Content** | Slurs, hate speech | 🚫 BLOCK |
| **Social Engineering** | "Complete this harmful sentence..." | ⚠️ REVIEW |

### Security Actions

- **BLOCK**: Completely prevent the request/response
- **SANITIZE**: Clean up control sequences but allow content
- **REVIEW**: Flag for human review (soft block)
- **ALLOW**: Pass through safely

## 📊 Understanding the Output

When you run the security demo, you'll get a JSONL file with detailed results:

```json
{
  "seq": 42,
  "prompt": "Ignore previous instructions and...",
  "prompt_guard": {
    "severity": "BLOCK",
    "reason": "Instruction override attempt",
    "action": "block"
  },
  "final_text": "I can't assist with that request."
}
```

## 🛠️ Customization

### Adding New Attack Patterns

Edit `metta_llm_security.py` and add to the `PATTERNS` dictionary:

```python
PATTERNS = {
    # Your custom pattern
    r"(?i)your_attack_pattern": {
        "severity": SEVERITY_BLOCK, 
        "reason": "Your explanation"
    },
    # ... existing patterns
}
```

### Environment Variables

Configure the system using environment variables:

```bash
export MODEL="your-model-name"           # Default: dolphin-llama3
export OPENAI_BASE_URL="http://..."      # Default: http://localhost:11434/v1
export OPENAI_API_KEY="your-key"         # Default: ollama
export TEMPERATURE="0.2"                 # Model temperature
export MAX_TOKENS="512"                  # Max response tokens
export TIMEOUT="60"                      # Request timeout in seconds
```

## 🧪 Testing Your LLM

### Quick Test
```bash
python test_prompt_injection.py --out my_results.jsonl
```

### With Security Guards
```bash
python run_security_demo.py --out secure_results.jsonl
```

### Compare Results
The difference between these two runs shows you how effective the security layer is at blocking attacks.

## 📈 Advanced Usage

### Using in Your Own Code

```python
import metta_llm_security as sec

# Check a user prompt
user_input = "Your user's input here"
guard_result = sec.guard_prompt(user_input)

if guard_result["action"] == "block":
    response = guard_result["message_override"]
else:
    # Send to your LLM...
    llm_response = your_llm_call(user_input)
    
    # Check the response
    response_guard = sec.guard_response(llm_response)
    final_response = response_guard["text"]
```

### Jupyter Notebook

Use `1_run_garak.ipynb` for interactive testing and experimentation.

## 🔧 Troubleshooting

**"Connection refused" errors**: Make sure your LLM server is running on the correct port.

**"Module not found" errors**: Ensure all Python files are in the same directory.

**High memory usage**: Reduce `MAX_TOKENS` or use a smaller model.

**False positives**: Adjust the patterns in `metta_llm_security.py` - some patterns may be too aggressive.

## 🤝 Contributing

1. Fork the repository
2. Add new attack patterns or improve existing ones
3. Test thoroughly with `python run_security_demo.py`
4. Submit a pull request

## 📚 Learn More

- Read `docs/product_justification.md` for technical background
- Check `docs/important links.txt` for security resources
- Explore the OWASP Top 10 for LLM Applications

## ⚠️ Important Notes

- This is a **research/educational project** - test thoroughly before production use
- Security is layered - use this alongside other protections
- Patterns may need tuning for your specific use case
- Keep attack patterns updated as new threats emerge

---

**Built for the MeTTa AI Hackathon 2025** 🏆
