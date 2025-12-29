use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
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
    active_view: Option<Py<CypherView>>,
}

impl Drop for CypherCell {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[pyclass]
struct CypherView {
    parent: Py<CypherCell>,
    is_active: bool,
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
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "Failed to lock memory",
                    ));
                }
                const MADV_DONTFORK: i32 = 9;
                const MADV_DONTDUMP: i32 = 16;

                libc::madvise(ptr, len, MADV_DONTFORK);
                libc::madvise(ptr, len, MADV_DONTDUMP);
            }
            #[cfg(windows)]
            {
                if windows_sys::Win32::System::Memory::VirtualLock(ptr, len) == 0 {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "Failed to lock memory",
                    ));
                }
            }
        }
        Ok(())
    }

    fn wipe(&mut self) {
        if !self.wiped {
            let ptr = self.inner.as_ptr() as *mut std::ffi::c_void;
            let len = self.inner.len();
            unsafe {
                #[cfg(unix)]
                let _ = libc::munlock(ptr, len);
                #[cfg(windows)]
                let _ = windows_sys::Win32::System::Memory::VirtualUnlock(ptr, len);
            }
            self.inner.zeroize();
            self.wiped = true;
        }
    }
}

#[pymethods]
impl CypherCell {
    #[new]
    #[pyo3(signature = (data, volatile=false, ttl_sec=None))]
    fn new(data: Bound<'_, PyAny>, volatile: bool, ttl_sec: Option<u64>) -> PyResult<Self> {
        use pyo3::types::{PyByteArray, PyBytes, PyString};

        let bytes_data: Vec<u8> = if let Ok(py_bytes) = data.extract::<Bound<'_, PyBytes>>() {
            py_bytes.as_bytes().to_vec()
        } else if let Ok(py_ba) = data.extract::<Bound<'_, PyByteArray>>() {
            unsafe { py_ba.as_bytes().to_vec() }
        } else if let Ok(py_str) = data.extract::<Bound<'_, PyString>>() {
            py_str.encode_utf8()?.as_bytes().to_vec()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "data must be str, bytes, or bytearray",
            ));
        };

        let cell = CypherCell {
            inner: Zeroizing::new(bytes_data),
            volatile,
            wiped: false,
            birth: Instant::now(),
            ttl: ttl_sec.map(Duration::from_secs),
            active_view: None,
        };

        cell.try_lock()?;
        Ok(cell)
    }

    #[classmethod]
    fn from_env(_cls: &Bound<'_, PyType>, var_name: &str, volatile: bool) -> PyResult<Self> {
        use std::env;

        let os_val = env::var_os(var_name)
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("Env var not found"))?;

        #[cfg(unix)]
        let raw_bytes = {
            use std::os::unix::ffi::OsStringExt;
            os_val.into_vec()
        };

        #[cfg(windows)]
        let raw_bytes = {
            use std::os::windows::ffi::OsStrExt;
            let wide_chars: Vec<u16> = os_val.encode_wide().collect();
            let mut wide_wrapper = Zeroizing::new(wide_chars);

            let utf8_str = String::from_utf16(&wide_wrapper).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("Invalid Unicode in env var")
            })?;

            let bytes = utf8_str.into_bytes();
            bytes
        };

        let cell = CypherCell {
            inner: Zeroizing::new(raw_bytes),
            volatile,
            wiped: false,
            birth: Instant::now(),
            ttl: None,
            active_view: None,
        };

        cell.try_lock()?;
        Ok(cell)
    }

    fn verify(&self, other: &[u8]) -> bool {
        if self.wiped || self.inner.len() != other.len() {
            return false;
        }
        self.inner.ct_eq(other).into()
    }

    fn compare(&self, other: PyRef<'_, Self>) -> PyResult<bool> {
        if self.wiped || other.wiped {
            return Err(pyo3::exceptions::PyValueError::new_err("Cell is wiped"));
        }
        if self.inner.len() != other.inner.len() {
            return Ok(false);
        }
        Ok(self.inner.ct_eq(&*other.inner).into())
    }

    fn __enter__(slf: Bound<'_, Self>) -> PyResult<Bound<'_, CypherView>> {
        let py = slf.py();

        {
            let mut slf_mut = slf.borrow_mut();
            if let Some(limit) = slf_mut.ttl {
                if slf_mut.birth.elapsed() > limit {
                    slf_mut.wipe();
                    return Err(pyo3::exceptions::PyValueError::new_err("TTL expired"));
                }
            }
            if slf_mut.wiped {
                return Err(pyo3::exceptions::PyValueError::new_err("Cell is wiped"));
            }
        }

        let cell_py: Py<CypherCell> = slf.clone().unbind();

        let view = CypherView {
            parent: cell_py,
            is_active: true,
        };
        let view_bound = Bound::new(py, view)?;

        slf.borrow_mut().active_view = Some(view_bound.clone().unbind());

        Ok(view_bound)
    }

    fn __exit__(
        &mut self,
        py: Python<'_>,
        _exc: Option<Bound<'_, PyAny>>,
        _val: Option<Bound<'_, PyAny>>,
        _tb: Option<Bound<'_, PyAny>>,
    ) {
        if let Some(view_py) = self.active_view.take() {
            if let Ok(mut view) = view_py.bind(py).try_borrow_mut() {
                view.is_active = false;
            }
        }
        if self.volatile {
            self.wipe();
        }
    }

    fn __repr__(&self) -> &'static str {
        "<CypherCell: [REDACTED]>"
    }
}

#[pymethods]
impl CypherView {
    fn __bytes__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        if !self.is_active {
            return Err(pyo3::exceptions::PyValueError::new_err("View expired"));
        }
        let mut parent = self.parent.bind(py).borrow_mut();

        if let Some(limit) = parent.ttl {
            if parent.birth.elapsed() > limit {
                parent.wipe();
                return Err(pyo3::exceptions::PyValueError::new_err("TTL expired"));
            }
        }
        if parent.wiped {
            return Err(pyo3::exceptions::PyValueError::new_err("Cell is wiped"));
        }

        Ok(PyBytes::new(py, &parent.inner))
    }

    fn __str__<'py>(&self, py: Python<'py>) -> PyResult<String> {
        let b = self.__bytes__(py)?;
        std::str::from_utf8(b.as_bytes())
            .map(|s| s.to_string())
            .map_err(|_| pyo3::exceptions::PyValueError::new_err("Invalid UTF-8"))
    }
}

#[pymodule]
fn cypher_cell(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CypherCell>()?;
    m.add_class::<CypherView>()?;
    Ok(())
}
