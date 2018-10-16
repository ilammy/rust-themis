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

//! Generating key material.
//!
//! This module contains functions for generating random key pairs for use by Themis.
//!
//! Currently Themis supports two key types: RSA and ECDSA. Most of the functions accept either,
//! but some work only with ECDSA. The resulting keys are faceless byte blobs so pay attention.

use std::ptr;

use bindings::{themis_gen_ec_key_pair, themis_gen_rsa_key_pair};
use error::{Error, ErrorKind, Result};

/// Generates a private-public pair of RSA keys.
///
/// # Panics
///
/// This function may panic in case of unrecoverable errors inside the library (e.g., out-of-memory
/// or assertion violations).
pub fn gen_rsa_key_pair() -> (Vec<u8>, Vec<u8>) {
    match try_gen_rsa_key_pair() {
        Ok(keys) => keys,
        Err(e) => panic!("themis_gen_rsa_key_pair() failed: {}", e),
    }
}

/// Generates a private-public pair of RSA keys.
fn try_gen_rsa_key_pair() -> Result<(Vec<u8>, Vec<u8>)> {
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
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
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
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(private_key_len <= private_key.capacity());
        debug_assert!(public_key_len <= public_key.capacity());
        private_key.set_len(private_key_len as usize);
        public_key.set_len(public_key_len as usize);
    }

    Ok((private_key, public_key))
}

/// Generates a private-public pair of ECDSA keys.
///
/// # Panics
///
/// This function may panic in case of unrecoverable errors inside the library (e.g., out-of-memory
/// or assertion violations).
pub fn gen_ec_key_pair() -> (Vec<u8>, Vec<u8>) {
    match try_gen_ec_key_pair() {
        Ok(keys) => keys,
        Err(e) => panic!("themis_gen_ec_key_pair() failed: {}", e),
    }
}

/// Generates a private-public pair of ECDSA keys.
fn try_gen_ec_key_pair() -> Result<(Vec<u8>, Vec<u8>)> {
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
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
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
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(private_key_len <= private_key.capacity());
        debug_assert!(public_key_len <= public_key.capacity());
        private_key.set_len(private_key_len as usize);
        public_key.set_len(public_key_len as usize);
    }

    Ok((private_key, public_key))
}
