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
    
    with pytest.raises(ValueError, match="TTL expired"):
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


def test_reveal_masked_partial():
    cell = CypherCell(b"supersecret")
    # Only last 4 chars visible
    masked = cell.reveal_masked(4)
    assert masked.endswith("cret")
    assert masked.startswith("*" * (len("supersecret") - 4))


def test_reveal_masked_full():
    cell = CypherCell(b"allvisible")
    # If suffix_len >= len, should show all
    masked = cell.reveal_masked(20)
    assert masked == "allvisible"


def test_reveal_masked_empty():
    cell = CypherCell(b"wipe-me", volatile=True)
    # Wipe the cell
    cell.reveal()
    with pytest.raises(ValueError, match="Cell is empty"):
        cell.reveal_masked(3)


def test_double_wipe():
    cell = CypherCell(b"doublewipe", volatile=True)
    cell.reveal()  # wipes
    # Wipe again should not error (simulate context exit)
    # Use the context manager protocol
    try:
        cell.__exit__(None, None, None)
    except Exception:
        pytest.fail("__exit__ raised unexpectedly on double wipe")
    with pytest.raises(ValueError):
        cell.reveal()


def test_ttl_zero():
    cell = CypherCell(b"instant-expire", ttl_sec=0)
    time.sleep(0.01)
    with pytest.raises(ValueError, match="TTL expired"):
        cell.reveal()


def test_bytes_input_and_unicode():
    # Accepts bytes, returns unicode string
    cell = CypherCell("unicodetest-✓".encode("utf-8"))
    result = cell.reveal()
    assert isinstance(result, str)
    assert "✓" in result