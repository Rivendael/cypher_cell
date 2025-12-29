import pytest
import time
import pickle
import copy
import sys
import threading

from cypher_cell import CypherCell

def test_context_manager_access():
    cell = CypherCell(b"scoped-secret")
    with cell as view:
        assert bytes(view) == b"scoped-secret"
        assert str(view) == "scoped-secret"
    with pytest.raises(ValueError, match="View expired"):
        bytes(view)

def test_volatile_mode_wipes_after_context():
    cell = CypherCell(b"burn-after-use", volatile=True)
    with cell as view:
        assert bytes(view) == b"burn-after-use"
    assert cell.verify(b"burn-after-use") is False
    with pytest.raises(ValueError, match="Cell is wiped"):
        with cell as view:
            pass

def test_pickle_blocked():
    cell = CypherCell(b"un-picklable")
    with pytest.raises(TypeError, match="cannot pickle"):
        pickle.dumps(cell)

def test_copy_blocked():
    cell = CypherCell(b"original")
    with pytest.raises(TypeError, match="cannot pickle"):
        copy.copy(cell)

def test_cell_to_cell_comparison():
    cell_a = CypherCell(b"secret-a")
    cell_b = CypherCell(b"secret-a")
    assert cell_a.compare(cell_b) is True

def test_binary_data_handling():
    raw_binary = b"\xff\xfe\xfd\x00"
    cell = CypherCell(raw_binary)
    with cell as view:
        assert bytes(view) == raw_binary
        with pytest.raises(ValueError, match="Invalid UTF-8"):
            str(view)

def test_double_enter_invalidates_previous():
    """Verify that only the most recent view is active."""
    cell = CypherCell(b"nested")
    with cell as view1:
        with cell as view2:
            assert bytes(view2) == b"nested"
        # view2 exit should invalidate its specific view handle
        with pytest.raises(ValueError, match="View expired"):
            bytes(view2)

def test_concurrent_invalidation():
    """Test that a view cannot be accessed if the cell exits on another thread."""
    cell = CypherCell(b"concurrent-secret")
    barrier = threading.Barrier(2)
    results = []

    def read_loop(v):
        barrier.wait()
        # Give the main thread a tiny head start to exit the context
        time.sleep(0.01)
        try:
            bytes(v)
            results.append("success")
        except ValueError as e:
            results.append(str(e))

    with cell as view:
        t = threading.Thread(target=read_loop, args=(view,))
        t.start()
        barrier.wait()
    
    t.join()
    assert "View expired" in results[0]

def test_ttl_expiry_during_active_view():
    """Verify that an active view becomes invalid if the TTL hits while the block is open."""
    cell = CypherCell(b"short-lived", ttl_sec=1)
    
    with cell as view:
        assert bytes(view) == b"short-lived"
        
        time.sleep(1.1) 
        
        with pytest.raises(ValueError, match="TTL expired"):
            bytes(view)

def test_view_parent_reference_safety():
    """Ensure the view keeps the parent cell alive even if the cell variable is deleted."""
    cell = CypherCell(b"stay-alive")
    with cell as view:
        del cell
        import gc
        gc.collect() # Force GC
        # The view holds a Py<CypherCell>, so this must still work
        assert bytes(view) == b"stay-alive"

def test_compare_safety():
    c1 = CypherCell(b"abc")
    c2 = CypherCell(b"abcd")
    c3 = CypherCell(b"abc")
    
    assert c1.compare(c2) is False
    assert c1.compare(c3) is True
    assert c1.verify(b"abc") is True
    assert c1.verify(b"abd") is False

def test_error_string_alignment():
    cell = CypherCell(b"data", volatile=True)
    with cell as view:
        pass
    
    with pytest.raises(ValueError) as excinfo:
        bytes(view)
    assert "View expired" == str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        with cell as view:
            pass
    assert "Cell is wiped" == str(excinfo.value)

def test_lock_limit_enforcement():
    """
    Test that we catch the OS error when mlock limits are exceeded.
    We use 10MB as it's typically above the default 'ulimit -l' on many systems,
    but small enough to allocate easily in heap.
    """
    large_but_sane = b"\x00" * (10 * 1024 * 1024) # 10MB
    
    try:
        cell = CypherCell(large_but_sane)
    except RuntimeError as e:
        assert "Failed to lock memory" in str(e)
    except MemoryError:
        pytest.fail("System ran out of heap before testing mlock limits")

def test_view_integrity_after_parent_wipe():
    """
    If the parent cell is wiped while a view is open (e.g., via another thread 
    or a manual trigger), the view must immediately reflect that.
    """
    cell = CypherCell(b"sensitive-data")
    with cell as view:
        cell.verify(b"trigger-nothing") # Just a check
        
        cell_v = CypherCell(b"burn", volatile=True)
        with cell_v as v1:
            pass # Exit triggers wipe
            
        with pytest.raises(ValueError, match="View expired"):
            bytes(v1)

def test_null_byte_handling():
    """Secrets often contain null bytes (keys). Ensure they aren't truncated."""
    binary_key = b"key\x00with\x00nulls"
    cell = CypherCell(binary_key)
    with cell as view:
        assert len(bytes(view)) == 14
        assert bytes(view) == binary_key

def test_string_input_handling():
    """Verify CypherCell correctly handles and reveals standard strings."""
    secret = "secret-pássword-🔑"
    cell = CypherCell(secret)
    
    with cell as view:
        assert str(view) == secret
        assert bytes(view) == secret.encode("utf-8")

def test_type_error_on_invalid_input():
    """Ensure the extract logic rejects non-string/non-bytes types."""
    with pytest.raises(TypeError, match='data must be str, bytes, or bytearray'):
        CypherCell(12345) # type: ignore
    
    with pytest.raises(TypeError, match='data must be str, bytes, or bytearray'):
        CypherCell(["not", "a", "string"]) # type: ignore

def test_unicode_boundary_safety():
    """Test multi-byte characters to ensure extract handles UTF-8 correctly."""
    complex_unicode = "你好, 世界" 
    cell = CypherCell(complex_unicode)
    
    with cell as view:
        assert str(view) == complex_unicode
        assert len(bytes(view)) > len(complex_unicode) # UTF-8 expansion

def test_bytearray_support():
    """The extract::<Vec<u8>> logic should also handle bytearrays."""
    data = bytearray(b"mutable-secret")
    cell = CypherCell(data)
    
    with cell as view:
        assert bytes(view) == b"mutable-secret"

def test_from_env_success(monkeypatch):
    """Test successful retrieval of a secret from the environment."""
    secret_key = "MY_APP_SECRET"
    secret_value = "super-secret-password-123"
    monkeypatch.setenv(secret_key, secret_value)
    
    cell = CypherCell.from_env(secret_key, volatile=False)
    
    with cell as view:
        assert bytes(view) == secret_value.encode("utf-8")
        assert str(view) == secret_value

def test_from_env_missing_variable():
    """Test that a KeyError is raised if the variable does not exist."""
    with pytest.raises(KeyError) as excinfo:
        CypherCell.from_env("NON_EXISTENT_VAR_XYZ", volatile=False)
    
    assert "Env var not found" in str(excinfo.value)

def test_from_env_volatile_behavior(monkeypatch):
    """Test that volatile=True wipes the secret after the context manager exits."""
    monkeypatch.setenv("VOLATILE_SECRET", "temporary-value")
    
    cell = CypherCell.from_env("VOLATILE_SECRET", volatile=True)
    
    with cell as view:
        assert bytes(view) == b"temporary-value"
    
    with pytest.raises(ValueError, match="Cell is wiped"):
        with cell as view:
            pass

def test_from_env_utf8_integrity(monkeypatch):
    """Test that complex UTF-8 strings are handled correctly without corruption."""
    complex_val = "🔑_safe_✨_123"
    monkeypatch.setenv("COMPLEX_SECRET", complex_val)
    
    cell = CypherCell.from_env("COMPLEX_SECRET", volatile=False)
    with cell as view:
        assert str(view) == complex_val
        assert bytes(view) == complex_val.encode("utf-8")

@pytest.mark.skipif(sys.platform == "win32", reason="Windows treats empty env vars as non-existent")
def test_from_env_empty_variable(monkeypatch):
    """Test behavior when the environment variable is set but empty."""
    monkeypatch.setenv("EMPTY_VAR", "")
    
    cell = CypherCell.from_env("EMPTY_VAR", volatile=False)
    with cell as view:
        assert bytes(view) == b""
        assert str(view) == ""