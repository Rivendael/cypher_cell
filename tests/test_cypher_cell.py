import pytest
import time
import gc
from cypher_cell import CypherCell

def test_basic_reveal():
    """Test that we can store and retrieve a secret normally."""
    secret = b"standard-secret"
    cell = CypherCell(secret)
    assert cell.reveal() == "standard-secret"
    # Ensure it doesn't wipe on reveal by default
    assert cell.reveal() == "standard-secret"

def test_volatile_mode():
    """Test that volatile=True wipes the secret after one read."""
    cell = CypherCell(b"one-time-use", volatile=True)
    assert cell.reveal() == "one-time-use"
    
    with pytest.raises(ValueError, match="Cell is empty"):
        cell.reveal()

def test_ttl_expiration():
    """Test that the secret is wiped after the TTL duration."""
    # Set a very short TTL
    cell = CypherCell(b"timed-secret", ttl_sec=1)
    
    # Read immediately should work
    assert cell.reveal() == "timed-secret"
    
    # Wait for expiration
    time.sleep(1.1)
    
    with pytest.raises(ValueError, match="Cell has expired"):
        cell.reveal()

def test_context_manager():
    """Test that the 'with' statement triggers a wipe on exit."""
    with CypherCell(b"context-secret") as cell:
        assert cell.reveal() == "context-secret"
    
    # Outside the block, it should be wiped
    with pytest.raises(ValueError, match="Cell is empty"):
        cell.reveal()

def test_repr_security():
    """Test that the secret never leaks in the string representation."""
    secret = b"my-private-password"
    cell = CypherCell(secret)
    representation = repr(cell)
    
    assert "my-private-password" not in representation
    assert "[REDACTED]" in representation

def test_manual_delete_and_gc():
    """Test that deleting the object and running GC doesn't crash."""
    cell = CypherCell(b"delete-me")
    del cell
    gc.collect() # Force garbage collection to trigger Rust's Drop