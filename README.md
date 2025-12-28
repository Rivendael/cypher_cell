
# cypher_cell

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

**How it works:**

`cypher_cell` uses Rust's safety and low-level memory control to allocate, lock, and zeroize memory. The Python API is simple and ergonomic, supporting context management, burn-after-read, and TTL expiry. The Rust backend leverages `mlock`/`VirtualLock` and the `zeroize` crate for robust security.

✨ Features
🔒 Memory Locking (mlock): Prevents secrets from being swapped to the hard drive (OS-level protection).

🧹 Guaranteed Zeroization: Memory is physically overwritten with zeros the moment the object is dropped or expires.

👻 Volatile Mode: "Burn-after-reading" logic—the cell wipes itself immediately after one access.

⏳ Time-To-Live (TTL): Secrets automatically vanish after a configurable duration.

🛡️ Anti-Leak repr: Prevents accidental logging; print(cell) always shows [REDACTED].

🚀 Installation
Bash

# Clone and build locally
git clone https://github.com/yourusername/cypher_cell.git
cd cypher_cell
pip install maturin
maturin develop
🛠 Usage
1. Basic Secure Vault
Keep a secret locked in RAM and ensure it is wiped as soon as you are done.

Python

from cypher_cell import CypherCell

# Use as a Context Manager for maximum safety
with CypherCell(b"super-secret-key") as cell:
    # Use the secret
    db_connect(cell.reveal())

# Memory is now zeroed and unlocked
### 2. The "Mission Impossible" Cell (Volatile + TTL)
Create a secret that disappears after one read **OR** 30 seconds, whichever comes first.

```python
vault = CypherCell(b"transient-key", volatile=True, ttl_sec=30)

# This works
print(vault.reveal())

# This raises a ValueError (already wiped)
print(vault.reveal())
```

### 3. Masked Debugging
Reveal only what you need for logs.

```python
cell = CypherCell(b"SK-7721-9904-1234")
print(cell.reveal_masked(suffix_len=4))
# Output: *************1234
```

---

## 🏗 Architecture

**cypher_cell** bridges Python with low-level Rust primitives:

- **Creation:** Data is copied into a `Vec<u8>` in Rust.
- **Locking:** We call `libc::mlock` (Unix) or `VirtualLock` (Windows) to pin the memory to RAM.
- **Destruction:** When the Python reference count hits zero or `__exit__` is called, Rust executes the `Drop` trait, which calls `zeroize` and then unlocks the memory.

---

## 🧪 Testing

The project includes a robust pytest suite to verify memory states:

```bash
pytest tests/
```

---

## ⚖️ License

MIT © Rivendael