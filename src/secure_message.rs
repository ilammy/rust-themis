// Copyright 2018 (c) rust-themis developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ptr;

use libc::{size_t, uint8_t};

use error::themis_status_t;

#[link(name = "themis")]
extern "C" {
    fn themis_gen_rsa_key_pair(
        private_key: *mut uint8_t,
        private_key_length: *mut size_t,
        public_key: *mut uint8_t,
        public_key_length: *mut size_t,
    ) -> themis_status_t;

    fn themis_gen_ec_key_pair(
        private_key: *mut uint8_t,
        private_key_length: *mut size_t,
        public_key: *mut uint8_t,
        public_key_length: *mut size_t,
    ) -> themis_status_t;
}

/// Generate a pair of private-public RSA keys.
pub fn gen_rsa_key_pair() -> Result<(Vec<u8>, Vec<u8>), i32> {
    let mut private_key = Vec::new();
    let mut public_key = Vec::new();
    let mut private_key_len = 0;
    let mut public_key_len = 0;

    unsafe {
        let status = themis_gen_rsa_key_pair(
            ptr::null_mut(),
            &mut private_key_len,
            ptr::null_mut(),
            &mut public_key_len,
        );
        if status != 14 {
            return Err(status);
        }
    }

    private_key.reserve(private_key_len);
    public_key.reserve(private_key_len);

    unsafe {
        let status = themis_gen_rsa_key_pair(
            private_key.as_mut_ptr(),
            &mut private_key_len,
            public_key.as_mut_ptr(),
            &mut public_key_len,
        );
        if status != 0 {
            return Err(status);
        }
        debug_assert!(private_key_len <= private_key.capacity());
        debug_assert!(public_key_len <= public_key.capacity());
        private_key.set_len(private_key_len as usize);
        public_key.set_len(public_key_len as usize);
    }

    Ok((private_key, public_key))
}

/// Generate a pair of private-public ECDSA keys.
pub fn gen_ec_key_pair() -> Result<(Vec<u8>, Vec<u8>), i32> {
    let mut private_key = Vec::new();
    let mut public_key = Vec::new();
    let mut private_key_len = 0;
    let mut public_key_len = 0;

    unsafe {
        let status = themis_gen_ec_key_pair(
            ptr::null_mut(),
            &mut private_key_len,
            ptr::null_mut(),
            &mut public_key_len,
        );
        if status != 14 {
            return Err(status);
        }
    }

    private_key.reserve(private_key_len);
    public_key.reserve(private_key_len);

    unsafe {
        let status = themis_gen_ec_key_pair(
            private_key.as_mut_ptr(),
            &mut private_key_len,
            public_key.as_mut_ptr(),
            &mut public_key_len,
        );
        if status != 0 {
            return Err(status);
        }
        debug_assert!(private_key_len <= private_key.capacity());
        debug_assert!(public_key_len <= public_key.capacity());
        private_key.set_len(private_key_len as usize);
        public_key.set_len(public_key_len as usize);
    }

    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_rsa() {
        let (private, public) = gen_rsa_key_pair().unwrap();
    }

    #[test]
    fn generate_ec() {
        let (private, public) = gen_rsa_key_pair().unwrap();
    }
}
