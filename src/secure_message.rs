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

    fn themis_secure_message_wrap(
        private_key: *const uint8_t,
        private_key_length: size_t,
        public_key: *const uint8_t,
        public_key_length: size_t,
        message: *const uint8_t,
        message_length: size_t,
        wrapped_message: *mut uint8_t,
        wrapped_message_length: *mut size_t,
    ) -> themis_status_t;

    fn themis_secure_message_unwrap(
        private_key: *const uint8_t,
        private_key_length: size_t,
        public_key: *const uint8_t,
        public_key_length: size_t,
        wrapped_message: *const uint8_t,
        wrapped_message_length: size_t,
        message: *mut uint8_t,
        message_length: *mut size_t,
    ) -> themis_status_t;
}

/// Generate a pair of private-public RSA keys.
pub fn gen_rsa_key_pair() -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut private_key = Vec::new();
    let mut public_key = Vec::new();
    let mut private_key_len = 0;
    let mut public_key_len = 0;

    unsafe {
        let error: Error = themis_gen_rsa_key_pair(
            ptr::null_mut(),
            &mut private_key_len,
            ptr::null_mut(),
            &mut public_key_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    private_key.reserve(private_key_len);
    public_key.reserve(private_key_len);

    unsafe {
        let error: Error = themis_gen_rsa_key_pair(
            private_key.as_mut_ptr(),
            &mut private_key_len,
            public_key.as_mut_ptr(),
            &mut public_key_len,
        ).into();
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

/// Generate a pair of private-public ECDSA keys.
pub fn gen_ec_key_pair() -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut private_key = Vec::new();
    let mut public_key = Vec::new();
    let mut private_key_len = 0;
    let mut public_key_len = 0;

    unsafe {
        let error: Error = themis_gen_ec_key_pair(
            ptr::null_mut(),
            &mut private_key_len,
            ptr::null_mut(),
            &mut public_key_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    private_key.reserve(private_key_len);
    public_key.reserve(private_key_len);

    unsafe {
        let error: Error = themis_gen_ec_key_pair(
            private_key.as_mut_ptr(),
            &mut private_key_len,
            public_key.as_mut_ptr(),
            &mut public_key_len,
        ).into();
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

/// Wrap a message into a secure message.
pub fn wrap(private_key: &[u8], public_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let (private_key_ptr, private_key_len) = into_raw_parts(private_key);
    let (public_key_ptr, public_key_len) = into_raw_parts(public_key);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut wrapped_message = Vec::new();
    let mut wrapped_message_len = 0;

    unsafe {
        let error: Error = themis_secure_message_wrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut wrapped_message_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    wrapped_message.reserve(wrapped_message_len);

    unsafe {
        let error: Error = themis_secure_message_wrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            message_ptr,
            message_len,
            wrapped_message.as_mut_ptr(),
            &mut wrapped_message_len,
        ).into();
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(wrapped_message_len <= wrapped_message.capacity());
        wrapped_message.set_len(wrapped_message_len as usize);
    }

    Ok(wrapped_message)
}

/// Unwrap a secure message into a message.
pub fn unwrap(
    private_key: &[u8],
    public_key: &[u8],
    wrapped_message: &[u8],
) -> Result<Vec<u8>, Error> {
    let (private_key_ptr, private_key_len) = into_raw_parts(private_key);
    let (public_key_ptr, public_key_len) = into_raw_parts(public_key);
    let (wrapped_message_ptr, wrapped_message_len) = into_raw_parts(wrapped_message);

    let mut message = Vec::new();
    let mut message_len = 0;

    unsafe {
        let error: Error = themis_secure_message_unwrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            wrapped_message_ptr,
            wrapped_message_len,
            ptr::null_mut(),
            &mut message_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    message.reserve(message_len);

    unsafe {
        let error: Error = themis_secure_message_unwrap(
            private_key_ptr,
            private_key_len,
            public_key_ptr,
            public_key_len,
            wrapped_message_ptr,
            wrapped_message_len,
            message.as_mut_ptr(),
            &mut message_len,
        ).into();
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
    use super::*;

    use error::ErrorKind;

    #[test]
    fn mode_encrypt_decrypt() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        let message = b"test message please ignore";

        let secure_message = wrap(&private, &public, message).unwrap();
        let recovered = unwrap(&private, &public, &secure_message).unwrap();

        assert_eq!(recovered, message);
    }

    #[test]
    fn mode_sign_verify() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        let message = b"test message please ignore";

        let secure_message = wrap(&private, &[], message).unwrap();
        let recovered = unwrap(&private, &public, &secure_message).unwrap();

        assert_eq!(recovered, message);
    }

    #[test]
    fn invalid_key() {
        let (private1, public1) = gen_ec_key_pair().unwrap();
        let (private2, public2) = gen_ec_key_pair().unwrap();
        let message = b"test message please ignore";

        let secure_message = wrap(&private1, &public1, message).unwrap();
        let error = unwrap(&private2, &public2, &secure_message).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    #[test]
    fn corrupted_data() {
        let (private, public) = gen_rsa_key_pair().unwrap();
        let message = b"test message please ignore";

        // TODO: investigate crashes in Themis
        // Using index "10" for example leads to a crash with SIGBUS, so Themis definitely
        // could use some audit because it does not really handle corrupted messages well.
        let mut secure_message = wrap(&private, &public, message).unwrap();
        secure_message[5] = 42;
        let error = unwrap(&private, &public, &secure_message).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidParameter);
    }
}
