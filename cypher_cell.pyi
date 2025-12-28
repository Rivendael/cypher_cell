from typing import Optional, Type
from types import TracebackType

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

    def __exit__(
        self, 
        exc_type: Optional[Type[BaseException]], 
        exc_value: Optional[BaseException], 
        traceback: Optional[TracebackType]
    ) -> None:
        """Exit the context manager, wiping the secret regardless of error state."""
        ...

    def reveal(self) -> str:
        """
        Reveal the stored secret as a string. 
        
        Raises:
            ValueError: If the cell is wiped, expired, or data is not valid UTF-8.
        """
        ...

    def reveal_bytes(self) -> bytes:
        """
        Reveal the stored secret as raw bytes. 
        
        Recommended for cryptographic keys or non-UTF-8 binary data.
        
        Raises:
            ValueError: If the cell is wiped or expired.
        """
        ...

    def reveal_masked(self, suffix_len: int) -> str:
        """
        Reveal the secret with all but the last suffix_len characters masked.
        Returns a redacted string like '*******1234'.
        """
        ...

    def wipe(self) -> None:
        """Manually wipe the secret from memory and release the OS memory lock."""
        ...

    def __repr__(self) -> str:
        """Returns '<CypherCell: [REDACTED]>' to prevent accidental logging."""
        ...

    def __str__(self) -> str:
        """Returns '<CypherCell: [REDACTED]>' to prevent accidental logging."""
        ...
    
    def reveal_bytes(self) -> bytes:
        """
        Reveal the stored secret as raw bytes. 
        
        Recommended for cryptographic keys or non-UTF-8 binary data.
        
        Raises:
            ValueError: If the cell is wiped or expired.
        """
        ...
    
    def __eq__(self, other: object) -> Exception:
        """
        Disable direct equality comparison to prevent timing attacks.
        Use the verify() method for constant-time comparison instead.
        """
        ...

    def __getstate__(self) -> Exception:
        """
        CypherCell objects cannot be serialized (pickled) for security reasons.
        """
        ...

    @classmethod
    def from_env(cls, var_name: str, volatile: bool = False) -> "CypherCell":
        """Load a secret directly from an environment variable."""
        ...

    def verify(self, other: bytes) -> bool:
        """
        Check if the secret matches the input using constant-time comparison.
        This protects against timing attacks.
        """
        ...