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
    pub fn new(private_key: D, public_key: E) -> Self {
        Self {
            private_key,
            public_key,
        }
    }

    pub fn wrap<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        wrap(
            self.private_key.as_ref(),
            self.public_key.as_ref(),
            message.as_ref(),
        )
    }

    pub fn unwrap<M: AsRef<[u8]>>(&self, wrapped: M) -> Result<Vec<u8>, Error> {
        unwrap(
            self.private_key.as_ref(),
            self.public_key.as_ref(),
            wrapped.as_ref(),
        )
    }
}

#[derive(Clone)]
pub struct SecureSign<D> {
    private_key: D,
}

impl<D> SecureSign<D>
where
    D: AsRef<[u8]>,
{
    pub fn new(private_key: D) -> Self {
        Self { private_key }
    }

    pub fn sign<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        wrap(self.private_key.as_ref(), &[], message.as_ref())
    }
}

#[derive(Clone)]
pub struct SecureVerify<E> {
    public_key: E,
}

impl<E> SecureVerify<E>
where
    E: AsRef<[u8]>,
{
    pub fn new(public_key: E) -> Self {
        Self { public_key }
    }

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

#[cfg(test)]
mod tests {
    use error::ErrorKind;
    use keygen::{gen_ec_key_pair, gen_rsa_key_pair};
    use secure_message::{SecureMessage, SecureSign, SecureVerify};

    #[test]
    fn mode_encrypt_decrypt() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        let secure = SecureMessage::new(private, public);

        let plaintext = b"test message please ignore";
        let wrapped = secure.wrap(&plaintext).expect("encryption");
        let recovered_message = secure.unwrap(&wrapped).expect("decryption");

        assert_eq!(recovered_message, plaintext);
    }

    #[test]
    fn mode_sign_verify() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        let sign = SecureSign::new(private);
        let verify = SecureVerify::new(public);

        let plaintext = b"test message please ignore";
        let signed_message = sign.sign(&plaintext).unwrap();
        let recovered_message = verify.verify(&signed_message).unwrap();

        assert_eq!(recovered_message, plaintext);
    }

    #[test]
    fn invalid_key() {
        let (private1, public1) = gen_ec_key_pair().unwrap();
        let (private2, public2) = gen_ec_key_pair().unwrap();
        let secure1 = SecureMessage::new(private1, public1);
        let secure2 = SecureMessage::new(private2, public2);

        let plaintext = b"test message please ignore";
        let wrapped = secure1.wrap(&plaintext).expect("encryption");
        let error = secure2.unwrap(&wrapped).expect_err("decryption error");

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    // TODO: investigate crashes in Themis
    // This test crashes with SIGSEGV as Themis seems to not verify correctness of private-public
    // keys. Maybe we will need to use newtype idiom to make sure that keys are not misplaced, or
    // we'd better fix the crash and produce an expected error.
    #[test]
    #[ignore]
    fn misplaced_keys() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        // Note that key parameters are in wrong order.
        let secure = SecureMessage::new(public, private);

        let plaintext = b"test message please ignore";
        let wrapped = secure.wrap(&plaintext).expect("encryption");
        let error = secure.unwrap(&wrapped).expect_err("decryption error");

        assert_eq!(error.kind(), ErrorKind::InvalidParameter);
    }

    #[test]
    fn corrupted_data() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        let secure = SecureMessage::new(private, public);

        // TODO: investigate crashes in Themis
        // Using index "10" for example leads to a crash with SIGBUS, so Themis definitely
        // could use some audit because it does not really handle corrupted messages well.
        let plaintext = b"test message please ignore";
        let mut wrapped = secure.wrap(&plaintext).expect("encryption");
        wrapped[5] = 42;
        let error = secure.unwrap(&wrapped).expect_err("decryption error");

        assert_eq!(error.kind(), ErrorKind::InvalidParameter);
    }
}
