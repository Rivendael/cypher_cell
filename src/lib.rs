use pyo3::prelude::*;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[pyclass]
struct CypherCell {
    inner: Vec<u8>,
    volatile: bool,
    birth: Instant,
    ttl: Option<Duration>,
}

impl CypherCell {
    fn lock_memory(&self) {
        let ptr = self.inner.as_ptr() as *const std::ffi::c_void;
        let len = self.inner.len();
        unsafe {
            cfg_if::cfg_if! {
                if #[cfg(unix)] {
                    let _ = libc::mlock(ptr, len);
                } else if #[cfg(windows)] {
                    let _ = windows_sys::Win32::System::Memory::VirtualLock(ptr, len);
                }
            }
        }
    }

    fn unlock_memory(&self) {
        let ptr = self.inner.as_ptr() as *const std::ffi::c_void;
        let len = self.inner.len();
        unsafe {
            cfg_if::cfg_if! {
                if #[cfg(unix)] {
                    let _ = libc::munlock(ptr, len);
                } else if #[cfg(windows)] {
                    let _ = windows_sys::Win32::System::Memory::VirtualUnlock(ptr, len);
                }
            }
        }
    }

    fn wipe(&mut self) {
        self.unlock_memory();
        self.inner.zeroize();
    }
}

#[pymethods]
impl CypherCell {
    #[new]
    #[pyo3(signature = (data, volatile=false, ttl_sec=None))]
    fn new(data: &[u8], volatile: bool, ttl_sec: Option<u64>) -> Self {
        let cell = CypherCell {
            inner: data.to_vec(),
            volatile,
            birth: Instant::now(),
            ttl: ttl_sec.map(Duration::from_secs),
        };
        cell.lock_memory();
        cell
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(&mut self, _exc: Py<PyAny>, _val: Py<PyAny>, _tb: Py<PyAny>) {
        self.wipe();
    }

    fn reveal(&mut self) -> PyResult<String> {
        if let Some(limit) = self.ttl {
            if self.birth.elapsed() > limit {
                self.wipe();
                return Err(pyo3::exceptions::PyValueError::new_err("TTL expired"));
            }
        }

        if self.inner.iter().all(|&x| x == 0) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Cell is empty/wiped.",
            ));
        }

        let secret = String::from_utf8_lossy(&self.inner).to_string();

        if self.volatile {
            self.wipe();
        }

        Ok(secret)
    }

    fn reveal_masked(&self, suffix_len: usize) -> PyResult<String> {
        if self.inner.iter().all(|&x| x == 0) {
            return Err(pyo3::exceptions::PyValueError::new_err("Cell is empty"));
        }

        let len = self.inner.len();
        if suffix_len >= len {
            return Ok(String::from_utf8_lossy(&self.inner).to_string());
        }

        let mask_part = "*".repeat(len - suffix_len);
        let visible_part = String::from_utf8_lossy(&self.inner[len - suffix_len..]);
        
        Ok(format!("{}{}", mask_part, visible_part))
    }

    fn __repr__(&self) -> &'static str {
        "<CypherCell: [REDACTED]>"
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
