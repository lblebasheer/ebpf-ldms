use std::ffi::{c_char, c_int, c_ulonglong};

#[repr(C)] pub struct ldms_log_fn_t { _private: [u8; 0] }
#[repr(C)] pub struct attr_value_list { _private: [u8; 0] }
#[repr(C)] pub struct ldms_t { _private: [u8; 0] }
#[repr(C)] pub struct ldms_event_cb_t { _private: [u8; 0] }
#[repr(C)] pub struct cb_arg { _private: [u8; 0] }

#[link(name = "ldms",)]
#[link(name = "ldmsd_stream")]
unsafe extern "C" {
    pub fn ldms_xprt_new_with_auth(
            xprt_name: *const c_char,
            log_fn: *const ldms_log_fn_t,
            auth_name: *const c_char,
            auth_av_list: *const attr_value_list) -> *const ldms_t;

    pub fn ldms_xprt_connect_by_name(
            x: *const ldms_t,
            host: *const c_char,
            port: *const c_char,
            cb: *const ldms_event_cb_t,
            cb_arg: *const cb_arg) -> c_int;

    pub fn ldmsd_stream_publish(
            x: *const ldms_t,
            stream_name: *const c_char,
            stream_type: ldmsd_stream_type_t,
            data: *const c_char,
            data_len: c_ulonglong) -> c_int;
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum ldmsd_stream_type_t {
    LDMSD_STREAM_STRING = 0,
    LDMSD_STREAM_JSON = 1,
}
