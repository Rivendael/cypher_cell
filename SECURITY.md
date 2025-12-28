Security Policy

## Reporting a Vulnerability
Please do not report security vulnerabilities through public GitHub issues.

If you discover a potential security flaw in cypher_cell, please report it by:
- Opening a Draft Security Advisory on GitHub (preferred).
- Or by emailing [riverb514@gmail.com].

Please include:
- A description of the vulnerability.
- A proof-of-concept (PoC) script.
- Details of the environment (OS, Python version, Rust version).

We aim to acknowledge all reports within 48 hours and provide a fix or a public mitigation strategy within 30 days.

## Threat Model & Scope
cypher_cell is designed to protect secrets in the Memory (RAM) layer of the stack.

### In Scope
We consider the following to be high-priority vulnerabilities:
- Zeroization Failure: Secrets remaining in the Rust-allocated memory after `wipe()` or `Drop`.
- Locking Bypass: Situations where memory marked for locking is successfully moved to swap space.
- Timing Attacks: Non-constant-time behavior in the `verify()` method.
- Logic Flaws: Circumventing the volatile or TTL protections.

### Out of Scope (Known Limitations)
Due to the nature of the Python interpreter, the following are known limitations and are not considered vulnerabilities of this library:
- Pre-Ingestion Leaks: Secrets existing in the Python heap before being passed to CypherCell (unless using `from_env`).
- Post-Reveal Leaks: The fact that `reveal()` creates an immutable Python `str` or `bytes` object that remains under the control of the Python Garbage Collector.
- Root-level Access: An attacker with root or SYSTEM privileges can bypass mlock protections via debugger attachments (e.g., ptrace, WinDbg).

## Security Best Practices for Users
To ensure the maximum effectiveness of cypher_cell, users should:
- Use CypherCell as a context manager (`with` statement) to ensure deterministic wiping.
- Minimize the lifetime of the string returned by `.reveal()`.
- Disable core dumps in production environments.
- Use `reveal_bytes()` for high-entropy keys to avoid Python string interning.
