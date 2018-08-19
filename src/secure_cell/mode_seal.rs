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
use secure_cell::SecureCell;
use utils::into_raw_parts;

#[link(name = "themis")]
extern "C" {
    fn themis_secure_cell_encrypt_seal(
        master_key: *const uint8_t,
        master_key_length: size_t,
        user_context: *const uint8_t,
        user_context_length: size_t,
        message: *const uint8_t,
        message_length: size_t,
        encrypted_message: *mut uint8_t,
        encrypted_message_length: *mut size_t,
    ) -> themis_status_t;

    fn themis_secure_cell_decrypt_seal(
        master_key: *const uint8_t,
        master_key_length: size_t,
        user_context: *const uint8_t,
        user_context_length: size_t,
        encrypted_message: *const uint8_t,
        encrypted_message_length: size_t,
        plain_message: *mut uint8_t,
        plain_message_length: *mut size_t,
    ) -> themis_status_t;
}

pub struct SecureCellSeal<K, C>(pub(crate) SecureCell<K, C>);

impl<K, C> SecureCellSeal<K, C>
    where
        K: AsRef<[u8]>,
        C: AsRef<[u8]>,
{
    pub fn encrypt<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        encrypt_seal(self.0.master_key(), self.0.user_context(), message.as_ref())
    }

    pub fn decrypt<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        decrypt_seal(self.0.master_key(), self.0.user_context(), message.as_ref())
    }
}

/// Encrypts `message` with `master_key` including optional `user_context` for verification.
fn encrypt_seal(master_key: &[u8], user_context: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (user_context_ptr, user_context_len) = into_raw_parts(user_context);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut encrypted_message = Vec::new();
    let mut encrypted_message_len = 0;

    unsafe {
        let error: Error = themis_secure_cell_encrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut encrypted_message_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    encrypted_message.reserve(encrypted_message_len as usize);

    unsafe {
        let error: Error = themis_secure_cell_encrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            encrypted_message.as_mut_ptr(),
            &mut encrypted_message_len,
        ).into();
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(encrypted_message_len <= encrypted_message.capacity());
        encrypted_message.set_len(encrypted_message_len as usize);
    }

    Ok(encrypted_message)
}

/// Decrypts `message` with `master_key` and verifies authenticity of `user_context`.
fn decrypt_seal(master_key: &[u8], user_context: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (user_context_ptr, user_context_len) = into_raw_parts(user_context);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut decrypted_message = Vec::new();
    let mut decrypted_message_len = 0;

    unsafe {
        let error: Error = themis_secure_cell_decrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut decrypted_message_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    decrypted_message.reserve(decrypted_message_len as usize);

    unsafe {
        let error: Error = themis_secure_cell_decrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            decrypted_message.as_mut_ptr(),
            &mut decrypted_message_len,
        ).into();
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(decrypted_message_len <= decrypted_message.capacity());
        decrypted_message.set_len(decrypted_message_len as usize);
    }

    Ok(decrypted_message)
}

#[cfg(test)]
mod tests {
    use error::ErrorKind;
    use secure_cell::SecureCell;

    #[test]
    fn happy_path() {
        let seal = SecureCell::with_key("deep secret").seal();

        let plaintext = b"example plaintext";
        let ciphertext = seal.encrypt(&plaintext).unwrap();
        let recovered = seal.decrypt(&ciphertext).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn invalid_key() {
        let seal1 = SecureCell::with_key(b"deep secret").seal();
        let seal2 = SecureCell::with_key(b"DEEP SECRET").seal();

        let plaintext = b"example plaintext";
        let ciphertext = seal1.encrypt(&plaintext).unwrap();
        let error = seal2.decrypt(&ciphertext).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    #[test]
    fn invalid_context() {
        let seal1 = SecureCell::with_key_and_context(b"deep secret", b"ctx1").seal();
        let seal2 = SecureCell::with_key_and_context(b"deep secret", b"ctx2").seal();

        let plaintext = b"example plaintext";
        let ciphertext = seal1.encrypt(&plaintext).unwrap();
        let error = seal2.decrypt(&ciphertext).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    #[test]
    fn corrupted_data() {
        let seal = SecureCell::with_key(b"deep secret").seal();

        let plaintext = b"example plaintext";
        let mut ciphertext = seal.encrypt(&plaintext).unwrap();
        ciphertext[10] = 42;
        let error = seal.decrypt(&ciphertext).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidParameter);
    }
}
