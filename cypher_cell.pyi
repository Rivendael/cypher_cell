from typing import Optional

class CypherCell:
    def __init__(self, data: bytes, volatile: bool = False, ttl_sec: Optional[int] = None) -> None:
        """Create a new CypherCell containing secret data.
        Args:
            data: The secret bytes to store securely.
            volatile: If True, the secret is wiped after first reveal.
            ttl_sec: Optional time-to-live in seconds before the secret is wiped automatically.
        """
        ...

    def __enter__(self) -> "CypherCell":
        """Enter a context manager, returning self. Wipes the secret on context exit."""
        ...

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        """Exit the context manager, wiping the secret regardless of error state."""
        ...

    def reveal(self) -> str:
        """Reveal the stored secret as a string. May raise if wiped or expired."""
        ...

    def reveal_masked(self, suffix_len: int) -> str:
        """Reveal the secret with all but the last suffix_len characters masked."""
        ...

    def wipe(self) -> None:
        """Manually wipe the secret from memory, making it unrecoverable."""
        ...

    def __repr__(self) -> str:
        """Return a string representation that never reveals the secret value."""
        ...