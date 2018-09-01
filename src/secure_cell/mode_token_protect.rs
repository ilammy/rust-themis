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
    fn themis_secure_cell_encrypt_token_protect(
        master_key: *const uint8_t,
        master_key_length: size_t,
        user_context: *const uint8_t,
        user_context_length: size_t,
        message: *const uint8_t,
        message_length: size_t,
        token: *mut uint8_t,
        token_length: *mut size_t,
        encrypted_message: *mut uint8_t,
        encrypted_message_length: *mut size_t,
    ) -> themis_status_t;

    fn themis_secure_cell_decrypt_token_protect(
        master_key: *const uint8_t,
        master_key_length: size_t,
        user_context: *const uint8_t,
        user_context_length: size_t,
        encrypted_message: *const uint8_t,
        encrypted_message_length: size_t,
        token: *const uint8_t,
        token_length: size_t,
        plain_message: *mut uint8_t,
        plain_message_length: *mut size_t,
    ) -> themis_status_t;
}

pub struct SecureCellTokenProtect<K, C>(pub(crate) SecureCell<K, C>);

impl<K, C> SecureCellTokenProtect<K, C>
where
    K: AsRef<[u8]>,
    C: AsRef<[u8]>,
{
    pub fn encrypt<M: AsRef<[u8]>>(&self, message: M) -> Result<(Vec<u8>, Vec<u8>), Error> {
        encrypt_token_protect(self.0.master_key(), self.0.user_context(), message.as_ref())
    }

    pub fn decrypt<M: AsRef<[u8]>, T: AsRef<[u8]>>(
        &self,
        message: M,
        token: T,
    ) -> Result<Vec<u8>, Error> {
        decrypt_token_protect(
            self.0.master_key(),
            self.0.user_context(),
            message.as_ref(),
            token.as_ref(),
        )
    }
}

/// Encrypts `message` with `master_key` including optional `user_context` for verification.
/// Returns `(ciphertext, auth_token)` tuple.
fn encrypt_token_protect(
    master_key: &[u8],
    user_context: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (user_context_ptr, user_context_len) = into_raw_parts(user_context);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut token = Vec::new();
    let mut token_len = 0;
    let mut encrypted_message = Vec::new();
    let mut encrypted_message_len = 0;

    unsafe {
        let status = themis_secure_cell_encrypt_token_protect(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut token_len,
            ptr::null_mut(),
            &mut encrypted_message_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    token.reserve(token_len as usize);
    encrypted_message.reserve(encrypted_message_len as usize);

    unsafe {
        let status = themis_secure_cell_encrypt_token_protect(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            token.as_mut_ptr(),
            &mut token_len,
            encrypted_message.as_mut_ptr(),
            &mut encrypted_message_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::Success {
            return Err(error);
        }
        debug_assert!(token_len <= token.capacity());
        token.set_len(token_len as usize);
        debug_assert!(encrypted_message_len <= encrypted_message.capacity());
        encrypted_message.set_len(encrypted_message_len as usize);
    }

    Ok((encrypted_message, token))
}

/// Decrypts `message` with `master_key` and `token` verifying `user_context`.
fn decrypt_token_protect(
    master_key: &[u8],
    user_context: &[u8],
    message: &[u8],
    token: &[u8],
) -> Result<Vec<u8>, Error> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (user_context_ptr, user_context_len) = into_raw_parts(user_context);
    let (message_ptr, message_len) = into_raw_parts(message);
    let (token_ptr, token_len) = into_raw_parts(token);

    let mut decrypted_message = Vec::new();
    let mut decrypted_message_len = 0;

    unsafe {
        let status = themis_secure_cell_decrypt_token_protect(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            token_ptr,
            token_len,
            ptr::null_mut(),
            &mut decrypted_message_len,
        );
        let error = Error::from_themis_status(status);
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    decrypted_message.reserve(decrypted_message_len as usize);

    unsafe {
        let status = themis_secure_cell_decrypt_token_protect(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            token_ptr,
            token_len,
            decrypted_message.as_mut_ptr(),
            &mut decrypted_message_len,
        );
        let error = Error::from_themis_status(status);
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
        let cell = SecureCell::with_key(b"deep secret").token_protect();

        let plaintext = b"example plaintext";
        let (ciphertext, token) = cell.encrypt(&plaintext).unwrap();
        let recovered = cell.decrypt(&ciphertext, &token).unwrap();

        assert_eq!(recovered, plaintext);

        assert_eq!(plaintext.len(), ciphertext.len());
    }

    #[test]
    fn invalid_key() {
        let cell1 = SecureCell::with_key(b"deep secret").token_protect();
        let cell2 = SecureCell::with_key(b"DEEP SECRET").token_protect();

        let plaintext = b"example plaintext";
        let (ciphertext, token) = cell1.encrypt(plaintext).unwrap();
        let error = cell2.decrypt(&ciphertext, &token).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    #[test]
    fn invalid_context() {
        let cell1 = SecureCell::with_key_and_context(b"deep secret", b"123").token_protect();
        let cell2 = SecureCell::with_key_and_context(b"deep secret", b"456").token_protect();

        let plaintext = b"example plaintext";
        let (ciphertext, token) = cell1.encrypt(plaintext).unwrap();
        let error = cell2.decrypt(&ciphertext, &token).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    #[test]
    fn corrupted_data() {
        let cell = SecureCell::with_key(b"deep secret").token_protect();

        let plaintext = b"example plaintext";
        let (mut ciphertext, token) = cell.encrypt(&plaintext).unwrap();
        ciphertext[10] = 42;
        let error = cell.decrypt(&ciphertext, &token).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Fail);
    }

    #[test]
    fn corrupted_token() {
        let cell = SecureCell::with_key(b"deep secret").token_protect();

        let plaintext = b"example plaintext";
        let (ciphertext, mut token) = cell.encrypt(&plaintext).unwrap();
        token[10] = 42;
        let error = cell.decrypt(&ciphertext, &token).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidParameter);
    }
}
