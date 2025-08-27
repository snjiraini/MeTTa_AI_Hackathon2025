## What is a Prompt Injection?

A prompt injection is a type of attack against large language models (LLMs) where malicious or manipulative instructions are embedded in the input text. These instructions try to override, hijack, or subvert the model’s intended behavior.

Think of it like SQL injection for databases, but instead of injecting code, the attacker injects text that makes the model misinterpret its instructions.

The security community widely recognizes prompt injection as one of the biggest threats to LLM safety. In fact, OWASP added “Prompt Injection” to its Top 10 for LLM security risks.

## Can MeTTa be used mitigate prompt injection
MeTTa can be a powerful component of a layered defense against prompt injection. It’s well suited to act as a symbolic policy-and-provenance layer that detects, rewrites, or blocks malicious/ambiguous instructions and generates explainable justification chains.

## How MeTTa helps (capabilities)

    - Knowledge-graph-native policies: represent instruction policies, templates, allowed operations, and provenance facts as graph facts that are easy to query and update.
    - Pattern matching & symbolic rules: detect injection patterns (e.g., “ignore previous instructions”, out-of-band delimiters, embedded code/execution requests) using concise rule definitions.
    - Self-reflection / meta-programming: dynamically adapt or tighten policies when new attack patterns are discovered (self-modifying guards).
    - Explainability: produce human-readable justification chains for why a prompt was blocked/rewritten (useful for audits and remediation).
    - Evidence aggregation: combine outputs from detectors (heuristic rules, specialized small models, embeddings similarity) and apply rules to reach decisions.