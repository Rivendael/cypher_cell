📦 cypher_cell
Hardened, self-destructing memory cells for Python secrets, powered by Rust.

Standard Python strings are vulnerable. They are immutable, interned, and stay in RAM long after you've finished with them. If a process is compromised or a memory dump is taken, your API keys and passwords are plain to see.

cypher_cell solves this by moving sensitive data into locked, zero-aware Rust memory segments.

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
2. The "Mission Impossible" Cell (Volatile + TTL)
Create a secret that disappears after one read OR 30 seconds, whichever comes first.

Python

vault = CypherCell(b"transient-key", volatile=True, ttl_sec=30)

# This works
print(vault.reveal()) 

# This raises a ValueError (already wiped)
print(vault.reveal()) 
3. Masked Debugging
Reveal only what you need for logs.

Python

cell = CypherCell(b"SK-7721-9904-1234")
print(cell.reveal_masked(suffix_len=4)) 
# Output: *************1234
🏗 Architecture
cypher_cell bridges Python with low-level Rust primitives:

Creation: Data is copied into a Vec<u8> in Rust.

Locking: We call libc::mlock (Unix) or VirtualLock (Windows) to pin the memory to RAM.

Destruction: When the Python reference count hits zero or __exit__ is called, Rust executes the Drop trait, which calls zeroize and then unlocks the memory.

🧪 Testing
The project includes a robust pytest suite to verify memory states:

Bash

pytest tests/
⚖️ License
MIT © Rivendael