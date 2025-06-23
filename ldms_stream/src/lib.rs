use anyhow::{Result, anyhow};
use std::ffi::CString;
use std::ptr;

mod raw;

pub struct SockStream {
    c_host: CString,
    c_port: CString,
    c_stream: CString,
    xprt_handle: *const raw::ldms_t,
}

unsafe impl Send for SockStream {}

impl SockStream {
    pub fn new(xprt: &str, auth: &str, host: &str, port: &str, stream: &str) -> Result<Self> {
        let c_xprt = match xprt {
            "sock" => Ok(CString::new(xprt)?),
            _ => Err(anyhow!("Unsupported or unimplemented transport: {}", xprt)),
        }?;
        let c_auth = match auth {
            "none" => Ok(CString::new(auth)?),
            "munge" => Ok(CString::new(auth)?),
            _ => Err(anyhow!(
                "Unsupported or unimplemented authentication: {}",
                auth
            )),
        }?;
        let c_host = CString::new(host)?;
        let c_port = CString::new(port)?;
        let c_stream = CString::new(stream)?;

        let null_log: *const raw::ldms_log_fn_t = ptr::null();
        let null_value: *const raw::attr_value_list = ptr::null();
        let xprt_handle = unsafe {
            raw::ldms_xprt_new_with_auth(c_xprt.as_ptr(), null_log, c_auth.as_ptr(), null_value)
        };
        if xprt_handle.is_null() {
            return Err(anyhow!(
                "ldms_xprt_new_with_auth: Failed to create new transport"
            ));
        }
        Ok(SockStream {
            c_host,
            c_port,
            c_stream,
            xprt_handle,
        })
    }

    pub fn connect(&mut self) -> Result<()> {
        let null_event: *const raw::ldms_event_cb_t = ptr::null();
        let null_arg: *const raw::cb_arg = ptr::null();

        let rc = unsafe {
            raw::ldms_xprt_connect_by_name(
                self.xprt_handle,
                self.c_host.as_ptr(),
                self.c_port.as_ptr(),
                null_event,
                null_arg,
            )
        };
        if rc != 0 {
            return Err(anyhow!(
                "ldms_xprt_connect_by_name: Failed to connect transport: {}",
                rc
            ));
        }
        Ok(())
    }

    pub fn ldms_stream_publish(&self, message: &str) -> Result<()> {
        let c_message = CString::new(message)?;

        let rc = unsafe {
            raw::ldmsd_stream_publish(
                self.xprt_handle,
                self.c_stream.as_ptr(),
                raw::ldmsd_stream_type_t::LDMSD_STREAM_JSON,
                c_message.as_ptr(),
                (c_message.count_bytes() + 1) as u64,
            )
        };
        if rc != 0 {
            return Err(anyhow!("ldmsd_steam_publish: failed: {}", rc));
        }
        Ok(())
    }
}
