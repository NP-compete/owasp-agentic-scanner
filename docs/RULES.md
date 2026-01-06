# Detection Rules Reference

Detailed explanation of each OWASP Agentic AI detection rule.

## AA01: Agent Goal Hijack

**Risk**: Attackers manipulate agent objectives through prompt injection or context manipulation.

**Patterns detected**:
- Direct prompt injection markers
- System prompt override attempts
- Goal/objective manipulation
- Context window attacks
- Instruction injection

**Example vulnerable code**:
```python
agent.run(user_input)  # Unvalidated user input
```

**Mitigation**: Validate and sanitize all inputs, use input/output guardrails.

---

## AA02: Tool Misuse & Exploitation

**Risk**: Agent tricked into misusing available tools for unintended purposes.

**Patterns detected**:
- Unrestricted tool access
- Missing tool validation
- Dynamic tool invocation without checks
- Tool chaining without limits

**Mitigation**: Implement tool allowlists, validate tool parameters, limit tool chaining depth.

---

## AA03: Identity & Privilege Abuse

**Risk**: Compromised credentials or excessive permissions granted to agents.

**Patterns detected**:
- Hardcoded credentials
- Excessive API permissions
- Missing authentication
- Privilege escalation patterns

**Mitigation**: Use least-privilege principles, rotate credentials, implement proper auth.

---

## AA04: Agentic Supply Chain

**Risk**: Malicious tools, models, or agent personas introduced via supply chain.

**Patterns detected**:
- Untrusted model sources
- Unverified plugin loading
- Dynamic code loading from external sources
- Missing integrity checks

**Mitigation**: Verify model/plugin sources, use checksums, pin versions.

---

## AA05: Unexpected Code Execution

**Risk**: Agent generates or executes attacker-controlled code.

**Patterns detected**:
- `eval()`, `exec()` usage
- Dynamic code generation
- LLM-generated code execution
- Unsafe deserialization

**Mitigation**: Never execute LLM-generated code without sandboxing and human review.

---

## AA06: Memory Poisoning

**Risk**: Malicious data injected into agent memory/context.

**Patterns detected**:
- Unvalidated memory writes
- Context injection
- Persistent memory without sanitization
- RAG poisoning patterns

**Mitigation**: Validate all data before storing, implement memory access controls.

---

## AA07: Excessive Agency

**Risk**: Agent operates without adequate human oversight.

**Patterns detected**:
- Autonomous action execution
- Missing confirmation prompts
- Unrestricted action loops
- No human-in-the-loop

**Mitigation**: Require human approval for sensitive actions, implement action limits.

---

## AA08: Insecure Plugin Design

**Risk**: Vulnerabilities in plugins or extensions used by agents.

**Patterns detected**:
- Unvalidated plugin inputs
- Missing plugin sandboxing
- Excessive plugin permissions
- Plugin injection vulnerabilities

**Mitigation**: Sandbox plugins, validate all plugin I/O, use least-privilege.

---

## AA09: Overreliance on Outputs

**Risk**: Blind trust in agent outputs without validation.

**Patterns detected**:
- Direct output usage without validation
- Missing output sanitization
- Trusting agent decisions without checks
- No output verification

**Mitigation**: Validate agent outputs, implement verification steps, add guardrails.

---

## AA10: Model Theft

**Risk**: Unauthorized access to proprietary models or model extraction attacks.

**Patterns detected**:
- Model weight exposure
- Unprotected model endpoints
- Missing access controls
- Model extraction patterns

**Mitigation**: Protect model assets, implement access controls, monitor for extraction attempts.
