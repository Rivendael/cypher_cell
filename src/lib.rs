use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyType};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[pyclass]
struct CypherCell {
    inner: Zeroizing<Vec<u8>>,
    volatile: bool,
    wiped: bool,
    birth: Instant,
    ttl: Option<Duration>,
}

impl CypherCell {
    fn try_lock(&self) -> PyResult<()> {
        let ptr = self.inner.as_ptr() as *mut std::ffi::c_void;
        let len = self.inner.len();

        if len == 0 {
            return Ok(());
        }

        unsafe {
            #[cfg(unix)]
            {
                if libc::mlock(ptr, len) != 0 {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to lock memory (mlock): {}",
                        std::io::Error::last_os_error()
                    )));
                }
                #[cfg(target_os = "linux")]
                {
                    // advise is "best effort" for hardening, but we'll still check
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTFORK);
                }
            }

            #[cfg(windows)]
            {
                if windows_sys::Win32::System::Memory::VirtualLock(ptr, len) == 0 {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                        "Failed to lock memory (VirtualLock): {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
        }
        Ok(())
    }

    fn try_unlock(&self) {
        let ptr = self.inner.as_ptr() as *mut std::ffi::c_void;
        let len = self.inner.len();
        unsafe {
            #[cfg(unix)]
            let _ = libc::munlock(ptr, len);
            #[cfg(windows)]
            let _ = windows_sys::Win32::System::Memory::VirtualUnlock(ptr, len);
        }
    }

    fn wipe(&mut self) {
        if !self.wiped {
            self.try_unlock();
            self.inner.zeroize();
            self.wiped = true;
        }
    }

    fn check_expiry_and_status(&mut self) -> PyResult<()> {
        if let Some(limit) = self.ttl {
            if self.birth.elapsed() > limit {
                self.wipe();
                return Err(pyo3::exceptions::PyValueError::new_err("TTL expired"));
            }
        }
        if self.wiped {
            return Err(pyo3::exceptions::PyValueError::new_err("Cell is wiped."));
        }
        Ok(())
    }
}

#[pymethods]
impl CypherCell {
    #[new]
    #[pyo3(signature = (data, volatile=false, ttl_sec=None))]
    fn new(data: &[u8], volatile: bool, ttl_sec: Option<u64>) -> PyResult<Self> {
        let cell = CypherCell {
            inner: Zeroizing::new(data.to_vec()),
            volatile,
            wiped: false,
            birth: Instant::now(),
            ttl: ttl_sec.map(Duration::from_secs),
        };
        cell.try_lock()?; // Use ? to propagate the error to Python
        Ok(cell)
    }

    #[classmethod]
    #[pyo3(signature = (var_name, volatile=false))]
    fn from_env(_cls: &Bound<'_, PyType>, var_name: &str, volatile: bool) -> PyResult<Self> {
        let mut val = std::env::var(var_name)
            .map_err(|_| pyo3::exceptions::PyKeyError::new_err("Env var not found"))?
            .into_bytes();

        let cell = CypherCell {
            inner: Zeroizing::new(val.clone()),
            volatile,
            wiped: false,
            birth: Instant::now(),
            ttl: None,
        };

        let lock_result = cell.try_lock();
        val.zeroize(); // Clean up intermediate copy even if lock fails

        lock_result?;
        Ok(cell)
    }

    fn verify(&self, other: &[u8]) -> bool {
        if self.wiped || self.inner.len() != other.len() {
            return false;
        }
        self.inner.ct_eq(other).into()
    }

    fn reveal<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyString>> {
        self.check_expiry_and_status()?;

        let _ = std::str::from_utf8(&self.inner)
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Data is not valid UTF-8"))?;

        let secret = PyString::new(py, unsafe { std::str::from_utf8_unchecked(&self.inner) });

        if self.volatile {
            self.wipe();
        }
        Ok(secret)
    }

    fn reveal_bytes<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self.check_expiry_and_status()?;

        let bytes = PyBytes::new(py, &self.inner);
        if self.volatile {
            self.wipe();
        }
        Ok(bytes)
    }

    fn reveal_masked(&self, suffix_len: usize) -> PyResult<String> {
        if self.wiped {
            return Err(pyo3::exceptions::PyValueError::new_err("Cell is wiped."));
        }

        let len = self.inner.len();
        if suffix_len >= len {
            return Ok(String::from_utf8_lossy(&self.inner).to_string());
        }

        let mask_part = "*".repeat(len - suffix_len);
        let visible_part = String::from_utf8_lossy(&self.inner[len - suffix_len..]);
        Ok(format!("{}{}", mask_part, visible_part))
    }

    fn wipe_py(&mut self) {
        self.wipe();
    }

    fn __bytes__<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self.reveal_bytes(py)
    }

    fn __eq__(&self, _other: Bound<'_, PyAny>) -> PyResult<bool> {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "Direct equality comparison is disabled for security. Use .verify() for constant-time comparison."
        ))
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: Option<Bound<'_, PyAny>>,
        _exc_value: Option<Bound<'_, PyAny>>,
        _traceback: Option<Bound<'_, PyAny>>,
    ) {
        self.wipe();
    }

    fn __repr__(&self) -> &'static str {
        "<CypherCell: [REDACTED]>"
    }

    fn __str__(&self) -> &'static str {
        "<CypherCell: [REDACTED]>"
    }

    fn __getstate__(&self) -> PyResult<()> {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "CypherCell objects cannot be serialized (pickled) for security reasons.",
        ))
    }
}

impl Drop for CypherCell {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[pymodule]
fn cypher_cell(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CypherCell>()?;
    Ok(())
}
