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

//! Secure Message service.
//!
//! **Secure Message** is a lightweight service that can help deliver some message or data
//! to your peer in a secure manner.

use std::ptr;

use libc::{size_t, uint8_t};

use error::{themis_status_t, Error, ErrorKind};
use utils::into_raw_parts;

#[link(name = "themis")]
extern "C" {
    fn themis_secure_message_wrap(
        private_key: *const uint8_t,
        private_key_length: size_t,
        public_key: *const uint8_t,
        public_key_length: size_t,
        message: *const uint8_t,
        message_length: size_t,
        wrapped: *mut uint8_t,
        wrapped_length: *mut size_t,
    ) -> themis_status_t;

    fn themis_secure_message_unwrap(
        private_key: *const uint8_t,
        private_key_length: size_t,
        public_key: *const uint8_t,
        public_key_length: size_t,
        wrapped: *const uint8_t,
        wrapped_length: size_t,
        message: *mut uint8_t,
        message_length: *mut size_t,
    ) -> themis_status_t;
}

/// Secure Message encryption.
///
/// Messages produced by this object will be encrypted and verified for integrity.
#[derive(Clone)]
pub struct SecureMessage<D, E> {
    private_key: D,
    public_key: E,
}

impl<D, E> SecureMessage<D, E>
where
    D: AsRef<[u8]>,
    E: AsRef<[u8]>,
{
    /// Makes a new Secure Message using given keys.
    pub fn new(private_key: D, public_key: E) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    /// Wraps the provided message into a secure encrypted message.
    pub fn wrap<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        wrap(
            self.private_key.as_ref(),
            self.public_key.as_ref(),
            message.as_ref(),
        )
    }

    /// Unwraps an encrypted message back into its original form.
    pub fn unwrap<M: AsRef<[u8]>>(&self, wrapped: M) -> Result<Vec<u8>, Error> {
        unwrap(
            self.private_key.as_ref(),
            self.public_key.as_ref(),
            wrapped.as_ref(),
        )
    }
}

/// Secure Message signing.
///
/// Messages produced by this object will be signed and verified for integrity, but not encrypted.
///
/// The signatures can be checked with [`SecureVerify`].
///
/// [`SecureVerify`]: struct.SecureVerify.html
#[derive(Clone)]
pub struct SecureSign<D> {
    private_key: D,
}

impl<D> SecureSign<D>
where
    D: AsRef<[u8]>,
{
    /// Makes a new Secure Message using given private key.
    pub fn new(private_key: D) -> Self {
        Self { private_key }
    }

    /// Securely signs a message and returns it with signature attached.
    pub fn sign<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        wrap(self.private_key.as_ref(), &[], message.as_ref())
    }
}

/// Secure Message verification.
///
/// Verifies signatures produced by [`SecureSign`].
///
/// [`SecureSign`]: struct.SecureSign.html
#[derive(Clone)]
pub struct SecureVerify<E> {
    public_key: E,
}

impl<E> SecureVerify<E>
where
    E: AsRef<[u8]>,
{
    /// Makes a new Secure Message using given public key.
    pub fn new(public_key: E) -> Self {
        Self { public_key }
    }

    /// Verifies a signature and returns the original message.
    pub fn verify<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        unwrap(&[], self.public_key.as_ref(), message.as_ref())
    }
}

/// Wrap a message into a secure message.
fn wrap(private_key: &[u8], public_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let (private_key_ptr, private_key_len) = into_raw_parts(private_key);
    let (public_key_ptr, public_key_len) = into_raw_parts(public_key);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut wrapped = Vec::new();
    let mut wrapped_len = 0;

    unsafe {
        let status = themis_secure_message_wrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut wrapped_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    wrapped.reserve(wrapped_len);

    unsafe {
        let status = themis_secure_message_wrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            message_ptr,
            message_len,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(wrapped_len <= wrapped.capacity());
        wrapped.set_len(wrapped_len as usize);
    }

    Ok(wrapped)
}

/// Unwrap a secure message into a message.
fn unwrap(private_key: &[u8], public_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, Error> {
    let (private_key_ptr, private_key_len) = into_raw_parts(private_key);
    let (public_key_ptr, public_key_len) = into_raw_parts(public_key);
    let (wrapped_ptr, wrapped_len) = into_raw_parts(wrapped);

    let mut message = Vec::new();
    let mut message_len = 0;

    unsafe {
        let status = themis_secure_message_unwrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            wrapped_ptr,
            wrapped_len,
            ptr::null_mut(),
            &mut message_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    message.reserve(message_len);

    unsafe {
        let status = themis_secure_message_unwrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            wrapped_ptr,
            wrapped_len,
            message.as_mut_ptr(),
            &mut message_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(message_len <= message.capacity());
        message.set_len(message_len as usize);
    }

    Ok(message)
}
