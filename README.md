# cypher_cell

[![Python Versions](https://img.shields.io/pypi/pyversions/cypher_cell)](https://pypi.org/project/cypher_cell/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Unit Tests](https://github.com/Rivendael/cypher_cell/actions/workflows/CI.yml/badge.svg)](https://github.com/Rivendael/cypher_cell/actions/workflows/CI.yml)
[![Latest Release](https://img.shields.io/github/v/release/Rivendael/cypher_cell)](https://github.com/Rivendael/cypher_cell/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-lightgrey)](https://github.com/Rivendael/cypher_cell)
[![Rust Backend](https://img.shields.io/badge/backend-rust-orange)](https://github.com/Rivendael/cypher_cell)

**Hardened, self-destructing memory cells for Python secrets, powered by Rust.**

`cypher_cell` is a Python extension module (written in Rust) that provides a secure, zero-leakage memory container for sensitive data such as API keys, passwords, cryptographic material, and tokens. Unlike standard Python strings and bytes, which are immutable, interned, and can linger in RAM or swap, `cypher_cell` ensures your secrets are:

- **Locked in RAM:** Prevented from being swapped to disk using OS-level memory locking.
- **Zeroized:** Overwritten with zeros immediately when no longer needed, leaving no trace in memory.
- **Ephemeral:** Optionally destroyed after a single access or a configurable time-to-live (TTL).
- **Leak-resistant:** Never exposed in logs, tracebacks, or accidental prints.


## Why use cypher_cell?

Python's default memory model is not designed for handling secrets. Sensitive data can be copied, cached, or swapped to disk without your control. Attackers with access to memory dumps, swap files, or process introspection tools can easily recover secrets. `cypher_cell` is designed for developers and security engineers who need:

- In-memory protection for credentials in long-running apps, CLI tools, or servers
- Defense-in-depth for cryptographic operations
- Secure handling of ephemeral secrets (e.g., one-time tokens, session keys)
- Compliance with security standards that require memory zeroization


## Features

- **🔒 Memory Locking:** Prevents secrets from being swapped to disk (OS-level protection).
- **🧹 Guaranteed Zeroization:** Memory is physically overwritten with zeros the moment the object is dropped or expires.
- **👻 Volatile Mode:** "Burn-after-reading" logic—the cell wipes itself immediately after one access.
- **⏳ Time-To-Live (TTL):** Secrets automatically vanish after a configurable duration.
- **🛡️ Anti-Leak repr:** Prevents accidental logging; `print(cell)` always shows `[REDACTED]`.

---


## 🛡️ Advanced Hardening Features

`cypher_cell` includes several advanced memory and security hardening techniques beyond standard secret management:

| Feature            | Implementation         | Benefit                                                                 |
|--------------------|-----------------------|-------------------------------------------------------------------------|
| Direct Env Loading | `from_env`            | Secrets loaded directly from environment variables, never touching Python's heap. |
| Timing Protection  | `verify` (constant-time)| Protects against timing attacks by using constant-time comparison for secret verification. |
| Anti-Core Dump     | `MADV_DONTDUMP`       | On Linux, secrets are excluded from core dumps if the process crashes.   |
| Anti-Fork          | `MADV_DONTFORK`       | Prevents child processes from inheriting secret memory regions.          |
| Binary Safety      | `reveal_bytes`        | Safely handles raw cryptographic keys and binary secrets, even if not valid UTF-8. |

### Implementation Details

- **Direct Env Loading**: `CypherCell.from_env("VAR")` loads secrets directly from environment variables, minimizing exposure to Python's garbage-collected memory.
- **Timing Protection**: The `verify()` method uses constant-time comparison to prevent attackers from inferring secrets via timing analysis.
- **Anti-Core Dump**: On Linux, memory is marked with `MADV_DONTDUMP` so secrets are never written to disk in crash dumps.
- **Anti-Fork**: Memory is marked with `MADV_DONTFORK` so child processes cannot inherit secret memory.
- **Binary Safety**: `reveal_bytes()` allows safe handling of raw binary secrets (e.g., cryptographic keys) that may not be valid UTF-8, avoiding crashes and leaks.

---

## 🚀 Installation

Clone and build locally:

```bash
git clone https://github.com/yourusername/cypher_cell.git
cd cypher_cell
pip install maturin
maturin develop
```



## 🛠 Usage

> ⚠️ **Pro Tip:** To prevent the secret from ever hitting the Python heap, avoid `CypherCell(b"my-secret")`. Instead, use `CypherCell.from_env("MY_SECRET")` or (in future) `CypherCell.from_file("/path/to/key")` to load secrets directly from secure sources.

### 1. Basic Secure Vault
Keep a secret locked in RAM and ensure it is wiped as soon as you are done.

```python
from cypher_cell import CypherCell

# Use as a Context Manager for maximum safety
with CypherCell(b"super-secret-key") as cell:
    # Use the secret
    db_connect(cell.reveal())
# Memory is now zeroed and unlocked
```

### 2. "Mission Impossible" Cell (Volatile + TTL)
Create a secret that disappears after one read **or** 30 seconds, whichever comes first.

```python
vault = CypherCell(b"transient-key", volatile=True, ttl_sec=30)
print(vault.reveal())  # Works
print(vault.reveal())  # Raises ValueError (already wiped)
```

### 3. Masked Debugging
Reveal only what you need for logs.

```python
cell = CypherCell(b"SK-7721-9904-1234")
print(cell.reveal_masked(suffix_len=4))  # Output: *************1234
```

### 4. Load Secret Directly from Environment
Avoids Python heap exposure by loading secrets straight from environment variables.

```python
import os
from cypher_cell import CypherCell

os.environ["MY_SECRET"] = "env-value"
cell = CypherCell.from_env("MY_SECRET")
print(cell.reveal())  # env-value
```

### 5. Constant-Time Secret Verification
Protects against timing attacks when checking secrets.

```python
cell = CypherCell(b"top-secret")
if cell.verify(b"top-secret"):
    print("Access granted!")
else:
    print("Access denied!")
```

### 6. Safe Binary Secret Handling
Safely work with raw cryptographic keys or binary data.

```python
key = b"\x01\x02\x03\x04\x05\x06"
cell = CypherCell(key)
raw = cell.reveal_bytes()
assert raw == key
```

---


## 🏗 Architecture

**cypher_cell** bridges Python with low-level Rust primitives:

- **Creation:** Data is copied into a `Vec<u8>` in Rust.
- **Locking:** Calls `libc::mlock` (Unix) or `VirtualLock` (Windows) to pin memory to RAM.
- **Destruction:** When the Python reference count hits zero or `__exit__` is called, Rust executes the `Drop` trait, which calls `zeroize` and then unlocks the memory.

---


## Known Weaknesses & Usage Tips

While cypher_cell protects the data within its vault, the act of passing a string to `CypherCell` or calling `.reveal()` creates temporary copies in Python's unmanaged memory. For maximum security, use the context manager and minimize the lifetime of the revealed string.

**Note on `.reveal()`:** When you call `.reveal()`, Python creates a standard, immutable string. While cypher_cell wipes its own internal memory, it cannot wipe the string Python just created. Always use secrets in the narrowest scope possible:

Warning on Literals: Avoid passing string literals directly like CypherCell("my_secret"). Python may intern these strings, keeping them in memory for the duration of the process regardless of what cypher_cell does. Always load from environment variables, files, or buffers.

```python
# GOOD: String is short-lived
authenticate(cell.reveal())

# BAD: Secret lingers in the 'key' variable
key = cell.reveal()
authenticate(key)
```

---


## 🧪 Testing

Run the test suite with:

```bash
pytest tests/
```

---

## ⚖️ License

MIT © Rivendael