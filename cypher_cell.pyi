from typing import Optional, Type, Any, Union
from types import TracebackType

class CypherView:
    """
    An ephemeral view of the secret data, only valid within the 
    context manager block of a CypherCell.
    """
    def __bytes__(self) -> bytes:
        """Access the raw binary secret."""
        ...

    def __str__(self) -> str:
        """
        Access the secret as a UTF-8 string. 
        Raises ValueError if the internal data is not valid UTF-8.
        """
        ...

class CypherCell:
    def __init__(
        self, 
        data: Union[str, bytes], 
        volatile: bool = False, 
        ttl_sec: Optional[int] = None
    ) -> None:
        """
        Create a new CypherCell. 
        Accepts strings (converted to UTF-8) or raw bytes.
        Memory is immediately locked (mlock/VirtualLock).
        """
        ...

    @classmethod
    def from_env(cls, var_name: str, volatile: bool = False) -> "CypherCell":
        """Load a secret directly from an environment variable."""
        ...

    def __enter__(self) -> CypherView:
        """Returns a CypherView invalidated when the block exits."""
        ...
    
    def __exit__(
        self, 
        exc_type: Optional[Type[BaseException]], 
        exc_val: Optional[BaseException], 
        exc_tb: Optional[TracebackType]
    ) -> None:
        """Invalidates views and wipes memory if volatile=True."""
        ...

    def verify(self, other: bytes) -> bool:
        """Constant-time comparison against raw bytes."""
        ...

    def compare(self, other: "CypherCell") -> bool:
        """Constant-time comparison against another CypherCell."""
        ...

    def __repr__(self) -> str: ...

    # Security Blockers
    def __eq__(self, other: object) -> bool: ...
    def __copy__(self) -> "CypherCell": ...
    def __deepcopy__(self, memo: Any) -> "CypherCell": ...
    def __getstate__(self) -> Any: ...