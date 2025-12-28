import pytest
import time
import gc
import os
import pickle
import threading

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
    
    with pytest.raises(ValueError, match="Cell is wiped."):
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
    with pytest.raises(ValueError, match="Cell is wiped."):
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
    with pytest.raises(ValueError, match="Cell is wiped."):
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

def test_reveal_bytes_binary_data():
    """Test that reveal_bytes can handle raw binary that isn't valid UTF-8."""
    raw_data = b"\xff\xfe\xfd\x00\x01\x02"
    cell = CypherCell(raw_data)
    
    result = cell.reveal_bytes()
    assert isinstance(result, bytes)
    assert result == raw_data
    
    # We now expect a ValueError with our custom message
    with pytest.raises(ValueError, match="Data is not valid UTF-8"):
        cell.reveal()

def test_reveal_bytes_volatile():
    """Test that reveal_bytes also respects the volatile 'burn-after-reading' flag."""
    cell = CypherCell(b"volatile-bytes", volatile=True)
    assert cell.reveal_bytes() == b"volatile-bytes"
    
    with pytest.raises(ValueError, match="Cell is wiped."):
        cell.reveal_bytes()

def test_reveal_bytes_ttl():
    """Test that reveal_bytes respects the TTL expiration."""
    cell = CypherCell(b"expiring-bytes", ttl_sec=0)
    # Give the CPU a millisecond to let the clock tick
    time.sleep(0.01)
    
    with pytest.raises(ValueError, match="TTL expired"):
        cell.reveal_bytes()

def test_reveal_bytes_after_reveal_string():
    """Test that once a cell is wiped via reveal(), reveal_bytes() also fails."""
    cell = CypherCell(b"cross-check", volatile=True)
    cell.reveal() # Trigger volatile wipe
    
    with pytest.raises(ValueError, match="Cell is wiped."):
        cell.reveal_bytes()

def test_from_env_loading():
    """Test loading a secret directly from an environment variable."""
    os.environ["MY_APP_SECRET"] = "env-vault-test"
    try:
        # Load directly from env
        cell = CypherCell.from_env("MY_APP_SECRET", volatile=True)
        
        # Verify it loaded correctly
        assert cell.reveal() == "env-vault-test"
        
        # Verify volatile worked
        with pytest.raises(ValueError, match="Cell is wiped."):
            cell.reveal()
    finally:
        # Cleanup env for safety
        if "MY_APP_SECRET" in os.environ:
            del os.environ["MY_APP_SECRET"]

def test_from_env_missing():
    """Test that from_env raises KeyError if the variable doesn't exist."""
    with pytest.raises(KeyError):
        CypherCell.from_env("NON_EXISTENT_VAR_12345")

def test_verify_constant_time_logic():
    """Test the constant-time equality verification."""
    secret = b"secure-password-123"
    cell = CypherCell(secret)
    
    # Correct match
    assert cell.verify(b"secure-password-123") is True
    
    # Incorrect matches
    assert cell.verify(b"wrong-password") is False
    assert cell.verify(b"secure-password-122") is False # Off by one
    assert cell.verify(b"") is False # Empty

def test_verify_after_wipe():
    """Test that verify returns False once the cell is wiped."""
    cell = CypherCell(b"ephemeral", volatile=True)
    assert cell.verify(b"ephemeral") is True
    
    # Reveal triggers wipe
    cell.reveal()
    
    # Should now fail verification
    assert cell.verify(b"ephemeral") is False

def test_binary_reveal_bytes_hardened():
    """Test that reveal_bytes handles raw binary keys (important for crypto)."""
    # 32 bytes of high-entropy binary data (not valid UTF-8)
    raw_key = os.urandom(32)
    cell = CypherCell(raw_key)
    
    # reveal() should fail due to UTF-8 validation
    with pytest.raises(ValueError, match="Data is not valid UTF-8"):
        cell.reveal()
        
    # reveal_bytes() should work perfectly
    assert cell.reveal_bytes() == raw_key

def test_masked_reveal_logic():
    """Ensure reveal_masked works as expected (sanity check for the restored method)."""
    cell = CypherCell(b"1234567890")
    assert cell.reveal_masked(4) == "******7890"
    assert cell.reveal_masked(0) == "**********"
    assert cell.reveal_masked(10) == "1234567890"

def test_string_redaction():
    """Test that __str__ and __repr__ never leak the secret."""
    secret = b"super-sensitive-123"
    cell = CypherCell(secret)
    
    # Both should be redacted
    assert str(cell) == "<CypherCell: [REDACTED]>"
    assert repr(cell) == "<CypherCell: [REDACTED]>"
    # Ensure the secret isn't hidden inside the string representation
    assert "super-sensitive" not in str(cell)

def test_equality_disabled():
    """Test that direct equality is disabled to prevent non-constant-time leaks."""
    cell = CypherCell(b"password123")
    
    with pytest.raises(TypeError, match="Direct equality comparison is disabled"):
        # This should trigger our __eq__ override
        cell == "password123"

def test_bytes_magic_method():
    """Test the __bytes__ / reveal_bytes functionality."""
    raw_data = b"\x00\xFF\x00\xFF"
    cell = CypherCell(raw_data)
    
    # Test explicit reveal_bytes
    assert cell.reveal_bytes() == raw_data
    # Test the magic method used by bytes() cast
    assert bytes(cell) == raw_data

def test_masked_reveal_logic():
    """Test that reveal_masked provides the correct partial visibility."""
    cell = CypherCell(b"SECRET_KEY_12345")
    
    # Test suffix length
    masked = cell.reveal_masked(suffix_len=5)
    assert masked == "***********12345"
    
    # Test where suffix is longer than the secret
    assert cell.reveal_masked(suffix_len=50) == "SECRET_KEY_12345"

def test_verify_constant_time():
    """Test that the verify method works correctly for both success and failure."""
    cell = CypherCell(b"secure-hash")
    
    assert cell.verify(b"secure-hash") is True
    assert cell.verify(b"wrong-hash") is False
    assert cell.verify(b"short") is False

def test_pickle_disabled():
    """Test that CypherCell cannot be pickled/serialized."""
    cell = CypherCell(b"secret-data")
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(cell)

def test_large_secret_handling():
    """Test that larger binary data is handled correctly (e.g., a large key)."""
    large_secret = os.urandom(1024 * 10)  # 10KB secret
    cell = CypherCell(large_secret)
    
    assert cell.reveal_bytes() == large_secret
    # Ensure no crash on wipe
    cell.wipe_py()
    with pytest.raises(ValueError):
        cell.reveal_bytes()

def test_equality_disabled_exhaustive():
    """Verify that equality is blocked against all types."""
    cell = CypherCell(b"data")
    for other in [None, 123, ["data"], {"key": "val"}]:
        with pytest.raises(TypeError, match="Direct equality comparison is disabled"):
            cell == other

def test_concurrent_access_smoke():
    """Smoke test to ensure no crashes during concurrent access/wipe."""
    cell = CypherCell(b"thread-safe", volatile=True)
    
    def access():
        try:
            cell.reveal()
        except ValueError:
            pass # Wiped by another thread is fine, just shouldn't crash

    threads = [threading.Thread(target=access) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

def test_malformed_utf8_reveal():
    """Test that malformed UTF-8 is caught before creating a Python string."""
    # 0xFF is invalid UTF-8
    cell = CypherCell(b"valid" + b"\xff" + b"invalid")
    
    with pytest.raises(ValueError, match="Data is not valid UTF-8"):
        cell.reveal()
    
    # reveal_bytes should still work regardless of UTF-8 status
    assert b"\xff" in cell.reveal_bytes()

def test_empty_secret():
    """Test behavior with an empty byte string."""
    cell = CypherCell(b"")
    assert cell.reveal() == ""
    assert cell.reveal_bytes() == b""
    assert cell.reveal_masked(5) == ""
    assert cell.verify(b"") is True

def test_lock_failure_handling():
    large_amount = 10 * 1024 * 1024  # 10 MB
    try:
        _ = CypherCell(b"\x00" * large_amount)
    except RuntimeError as e:
        assert "Failed to lock memory" in str(e)
    except MemoryError:
        pass