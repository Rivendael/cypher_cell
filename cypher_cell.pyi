from typing import Optional, Type, Any, Callable, TypeVar, Union
from types import TracebackType

T = TypeVar("T")

class CypherCell:
    def __init__(self, data: Union[bytes, bytearray], volatile: bool = False, ttl_sec: Optional[int] = None) -> None:
        """
        Create a new CypherCell. 
        If a bytearray is provided, it will be wiped in-place after copying.
        """
        ...

    @classmethod
    def from_env(cls, var_name: str, volatile: bool = False) -> "CypherCell":
        """
        Load a secret directly from an environment variable. 
        On Unix, this uses zero-copy OsString conversion to minimize leaks.
        """
        ...

    def __enter__(self) -> "CypherCell": ...
    
    def __exit__(
        self, 
        exc_type: Optional[Type[BaseException]], 
        exc_val: Optional[BaseException], 
        exc_tb: Optional[TracebackType]
    ) -> None: ...

    def reveal(self) -> str:
        """Reveal as a UTF-8 string. Wipes if volatile=True."""
        ...

    def reveal_bytes(self) -> bytes:
        """Reveal as raw bytes. Wipes if volatile=True."""
        ...

    def reveal_masked(self, suffix_len: int) -> str:
        """Return a masked string representation."""
        ...

    def verify(self, other: bytes) -> bool:
        """Constant-time comparison against a raw byte string."""
        ...

    def compare(self, other: "CypherCell") -> bool:
        """Constant-time comparison against another CypherCell."""
        ...

    def wipe_py(self) -> None:
        """Explicitly wipe the secret (exposed to Python as wipe_py)."""
        ...

    def __bytes__(self) -> bytes:
        """Allows casting via bytes(cell). Wipes if volatile=True."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

    # Security Blockers - These raise TypeError if called
    def __eq__(self, other: object) -> bool: ...
    def __copy__(self) -> None: ...
    def __deepcopy__(self, memo: Any) -> None: ...
    def __getstate__(self) -> Any: ...