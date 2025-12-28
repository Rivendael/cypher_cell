use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};
use subtle::ConstantTimeEq;

#[pyclass]
struct CypherCell {
    inner: Zeroizing<Vec<u8>>,
    volatile: bool,
    wiped: bool,
    birth: Instant,
    ttl: Option<Duration>,
}

impl CypherCell {
    fn try_lock(&self) {
        let ptr = self.inner.as_ptr() as *mut std::ffi::c_void;
        let len = self.inner.len();
        unsafe {
            #[cfg(unix)]
            {
                let _ = libc::mlock(ptr, len);
                #[cfg(target_os = "linux")]
                {
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
                    let _ = libc::madvise(ptr, len, libc::MADV_DONTFORK);
                }
            }
            #[cfg(windows)]
            {
                let _ = windows_sys::Win32::System::Memory::VirtualLock(ptr, len);
            }
        }
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
    fn new(data: &[u8], volatile: bool, ttl_sec: Option<u64>) -> Self {
        let cell = CypherCell {
            inner: Zeroizing::new(data.to_vec()),
            volatile,
            wiped: false,
            birth: Instant::now(),
            ttl: ttl_sec.map(Duration::from_secs),
        };
        cell.try_lock();
        cell
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
        cell.try_lock();
        val.zeroize();
        Ok(cell)
    }

    fn verify(&self, other: &[u8]) -> bool {
        if self.wiped || self.inner.len() != other.len() {
            return false;
        }
        self.inner.ct_eq(other).into()
    }

    fn reveal(&mut self) -> PyResult<String> {
        self.check_expiry_and_status()?;

        let secret = String::from_utf8(self.inner.to_vec())
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Data is not valid UTF-8"))?;

        if self.volatile { self.wipe(); }
        Ok(secret)
    }

    fn reveal_bytes<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        self.check_expiry_and_status()?;

        let bytes = PyBytes::new(py, &self.inner);
        if self.volatile { self.wipe(); }
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

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> { slf }
    fn __exit__(&mut self, _e: Py<PyAny>, _v: Py<PyAny>, _t: Py<PyAny>) { self.wipe(); }
    fn __repr__(&self) -> &'static str { "<CypherCell: [REDACTED]>" }
}

impl Drop for CypherCell {
    fn drop(&mut self) { self.wipe(); }
}

#[pymodule]
fn cypher_cell(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CypherCell>()?;
    Ok(())
}