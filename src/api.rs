/* automatically generated by rust-bindgen */

extern "C" {
    pub fn run(
        i: *const ::std::os::raw::c_char,
        i_len: u32,
        o: *mut ::std::os::raw::c_char,
        o_len: *mut u32,
        err: *mut ::std::os::raw::c_char,
        char_len: *mut u32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn meter_gas(
        i: *const ::std::os::raw::c_char,
        i_len: u32,
        gas: *mut u64,
    ) -> ::std::os::raw::c_int;
}
