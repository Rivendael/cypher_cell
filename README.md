# cypher_cell

[![Python Versions](https://img.shields.io/pypi/pyversions/cypher_cell)](https://pypi.org/project/cypher_cell/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Unit Tests](https://github.com/Rivendael/cypher_cell/actions/workflows/CI.yml/badge.svg)](https://github.com/Rivendael/cypher_cell/actions/workflows/CI.yml)
[![Latest Release](https://img.shields.io/github/v/release/Rivendael/cypher_cell)](https://github.com/Rivendael/cypher_cell/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-lightgrey)](https://github.com/Rivendael/cypher_cell)
[![Rust Backend](https://img.shields.io/badge/backend-rust-orange)](https://github.com/Rivendael/cypher_cell)


**Hardened, self-destructing memory cells for Python secrets, powered by Rust.**


`cypher_cell` now uses a **Scoped View Pattern**: secrets are only accessible via a temporary `CypherView` handle, obtained by entering a context manager (`with` block). Sensitive data is not directly accessible from the `CypherCell` instance. The view is only valid within the context and is automatically invalidated when the block exits.

Key security features:
- **Locked in RAM:** Prevented from being swapped to disk using OS-level memory locking.
- **Zeroized:** Overwritten with zeros immediately when no longer needed, leaving no trace in memory.
- **Scoped Access:** Data is only accessible via a `CypherView` inside a `with` block. Access outside the block raises `ValueError: View expired`.
- **Volatile & TTL:** Optionally destroyed after a single access or a configurable time-to-live (TTL).
- **Leak-resistant:** Never exposed in logs, tracebacks, or accidental prints.


## Why use cypher_cell?

Python's default memory model is not designed for handling secrets. Sensitive data can be copied, cached, or swapped to disk without your control. Attackers with access to memory dumps, swap files, or process introspection tools can easily recover secrets. `cypher_cell` is designed for developers and security engineers who need:

- In-memory protection for credentials in long-running apps, CLI tools, or servers
- Defense-in-depth for cryptographic operations
- Secure handling of ephemeral secrets (e.g., one-time tokens, session keys)
- Compliance with security standards that require memory zeroization




## Features

- **String and Bytes Support:** `CypherCell` now accepts both `bytes` and `str` as input. Passing a string is supported for convenience, but is **less secure** than passing bytes (see below).
- **Scoped View Pattern:** Secrets are only accessible via a `CypherView` object, valid only inside a `with` block.
- **Automatic Invalidation:** Exiting the context manager invalidates the view; further access raises `ValueError: View expired`.
- **Volatile Mode:** If `volatile=True`, the cell is wiped (zeroized) immediately after the context exits.
- **TTL Enforcement:** Time-To-Live is checked both when entering the context and when accessing the view.
- **Memory Locking:** Prevents secrets from being swapped to disk (OS-level protection).
- **🛡️ Anti-Leak repr:** Prevents accidental logging; `print(cell)` always shows `[REDACTED]`.

---



## 🛡️ Advanced Hardening Features

`cypher_cell` includes advanced memory and security hardening:

| Feature            | Implementation         | Benefit                                                                 |
|--------------------|-----------------------|-------------------------------------------------------------------------|
| Direct Env Loading | `from_env`            | Secrets loaded directly from environment variables, never touching Python's heap. |
| Timing Protection  | `verify` (constant-time)| Protects against timing attacks by using constant-time comparison for secret verification. |
| Anti-Core Dump     | `MADV_DONTDUMP`       | On Linux, secrets are excluded from core dumps if the process crashes.   |
| Anti-Fork          | `MADV_DONTFORK`       | Prevents child processes from inheriting secret memory regions.          |
| Binary Safety      | `bytes(view)`         | Safely handles raw cryptographic keys and binary secrets, even if not valid UTF-8. |

### Implementation Details

- **Direct Env Loading**: `CypherCell.from_env("VAR")` loads secrets directly from environment variables, minimizing exposure to Python's garbage-collected memory.
- **Timing Protection**: The `verify()` method uses constant-time comparison to prevent attackers from inferring secrets via timing analysis.
- **Anti-Core Dump**: On Linux, memory is marked with `MADV_DONTDUMP` so secrets are never written to disk in crash dumps.
- **Anti-Fork**: Memory is marked with `MADV_DONTFORK` so child processes cannot inherit secret memory.
- **Binary Safety**: Use `bytes(view)` for raw binary secrets. Use `str(view)` for UTF-8 strings (raises if invalid).

---


## 🚀 Installation

Clone and build locally:

```bash
git clone https://github.com/Rivendael/cypher_cell.git
cd cypher_cell
pip install maturin
maturin develop
```




## 🛠 Usage

> ⚠️ **Pro Tip:** To prevent the secret from ever hitting the Python heap, avoid `CypherCell(b"my-secret")`. Instead, use `CypherCell.from_env("MY_SECRET")` or (in future) `CypherCell.from_file("/path/to/key")` to load secrets directly from secure sources.



### 1. Basic Secure Vault (Scoped View)
Keep a secret locked in RAM and ensure it is wiped as soon as you are done.

```python
from cypher_cell import CypherCell

# You can now pass either bytes or str to CypherCell:
with CypherCell("super-secret-key") as view:  # str input (less secure)
    secret_str = str(view)
    db_connect(secret_str)

with CypherCell(b"super-secret-key") as view:  # bytes input (recommended)
    secret_bytes = bytes(view)
    db_connect(secret_bytes)
# After the block, view is invalidated and memory is zeroed
```


### 2. "Mission Impossible" Cell (Volatile + TTL)
Create a secret that disappears after one read **or** 30 seconds, whichever comes first.

```python
vault = CypherCell(b"transient-key", volatile=True, ttl_sec=30)
with vault as view:
    print(bytes(view))  # Works
# After context exit, vault is wiped and cannot be accessed again
try:
    with vault as view:
        print(bytes(view))
except ValueError:
    print("Cell is wiped")
```


### 3. Load Secret Directly from Environment
Avoids Python heap exposure by loading secrets straight from environment variables.

```python
import os
from cypher_cell import CypherCell

os.environ["MY_SECRET"] = "env-value"
cell = CypherCell.from_env("MY_SECRET")
with cell as view:
    print(str(view))  # env-value
```


### 4. Constant-Time Secret Verification
Protects against timing attacks when checking secrets.

```python
cell = CypherCell(b"top-secret")
if cell.verify(b"top-secret"):
    print("Access granted!")
else:
    print("Access denied!")
```


### 5. Safe Binary Secret Handling
Safely work with raw cryptographic keys or binary data.

```python
key = b"\x01\x02\x03\x04\x05\x06"
cell = CypherCell(key)
with cell as view:
    raw = bytes(view)
    assert raw == key
```

### 6. Compare two CypherCell Objects

```python
# Compare two secure cells without revealing secrets to the Python heap
cell_a = CypherCell.from_env("MASTER_KEY")
cell_b = CypherCell(b"MASTER_KEY_VALUE")

if cell_a.compare(cell_b):
    print("Keys match!")
```

---



## 🏗 Architecture

**cypher_cell** bridges Python with low-level Rust primitives:

- **Creation:** Data is copied into a `Vec<u8>` in Rust and locked in RAM.
- **Scoped View:** Access to secrets is only possible via a temporary `CypherView` object, valid inside a context manager.
- **Locking:** Calls `libc::mlock` (Unix) or `VirtualLock` (Windows) to pin memory to RAM.
- **Destruction:** When the context exits or TTL expires, Rust executes the `Drop` trait, which calls `zeroize` and then unlocks the memory.

---


authenticate(key)


## Known Weaknesses & Usage Tips


Security Tip: While CypherCell safely locks and zeroizes the data it holds, passing a standard Python str or bytes literal (e.g., CypherCell("secret")) leaves a temporary copy in Python's unmanaged heap. For maximum protection against memory forensics, use CypherCell.from_env() or load secrets into a bytearray that you zero out manually after the cell is created.

```python
...existing code...
# GOOD: Data is short-lived and only accessible inside the context
with cell as view:
    authenticate(bytes(view))

# BAD: Secret lingers in the 'key' variable outside the context
with cell as view:
    key = bytes(view)
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