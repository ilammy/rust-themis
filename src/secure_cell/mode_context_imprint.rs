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
    fn themis_secure_cell_encrypt_context_imprint(
        master_key: *const uint8_t,
        master_key_length: size_t,
        message: *const uint8_t,
        message_length: size_t,
        context: *const uint8_t,
        context_length: size_t,
        encrypted_message: *mut uint8_t,
        encrypted_message_length: *mut size_t,
    ) -> themis_status_t;

    fn themis_secure_cell_decrypt_context_imprint(
        master_key: *const uint8_t,
        master_key_length: size_t,
        encrypted_message: *const uint8_t,
        encrypted_message_length: size_t,
        token: *const uint8_t,
        token_length: size_t,
        plain_message: *mut uint8_t,
        plain_message_length: *mut size_t,
    ) -> themis_status_t;
}

pub struct SecureCellContextImprint<K, C>(pub(crate) SecureCell<K, C>);

impl<K, C> SecureCellContextImprint<K, C>
where
    K: AsRef<[u8]>,
    C: AsRef<[u8]>,
{
    pub fn encrypt<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        encrypt_context_imprint(self.0.master_key(), message.as_ref(), self.0.user_context())
    }

    pub fn decrypt<M: AsRef<[u8]>>(&self, message: M) -> Result<Vec<u8>, Error> {
        decrypt_context_imprint(self.0.master_key(), message.as_ref(), self.0.user_context())
    }
}

/// Encrypts `message` with `master_key` including optional `context`.
fn encrypt_context_imprint(
    master_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (message_ptr, message_len) = into_raw_parts(message);
    let (context_ptr, context_len) = into_raw_parts(context);

    let mut encrypted_message = Vec::new();
    let mut encrypted_message_len = 0;

    unsafe {
        let error: Error = themis_secure_cell_encrypt_context_imprint(
            master_key_ptr,
            master_key_len,
            message_ptr,
            message_len,
            context_ptr,
            context_len,
            ptr::null_mut(),
            &mut encrypted_message_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    encrypted_message.reserve(encrypted_message_len as usize);

    unsafe {
        let error: Error = themis_secure_cell_encrypt_context_imprint(
            master_key_ptr,
            master_key_len,
            message_ptr,
            message_len,
            context_ptr,
            context_len,
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

/// Decrypts `message` with `master_key` and expected `context`, but do not verify data.
fn decrypt_context_imprint(
    master_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (message_ptr, message_len) = into_raw_parts(message);
    let (context_ptr, context_len) = into_raw_parts(context);

    let mut decrypted_message = Vec::new();
    let mut decrypted_message_len = 0;

    unsafe {
        let error: Error = themis_secure_cell_decrypt_context_imprint(
            master_key_ptr,
            master_key_len,
            message_ptr,
            message_len,
            context_ptr,
            context_len,
            ptr::null_mut(),
            &mut decrypted_message_len,
        ).into();
        if error.kind() != ErrorKind::BufferTooSmall {
            return Err(error);
        }
    }

    decrypted_message.reserve(decrypted_message_len as usize);

    unsafe {
        let error: Error = themis_secure_cell_decrypt_context_imprint(
            master_key_ptr,
            master_key_len,
            message_ptr,
            message_len,
            context_ptr,
            context_len,
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
        let cell = SecureCell::with_key_and_context(b"deep secret", b"123").context_imprint();

        let plaintext = b"example plaintext";
        let ciphertext = cell.encrypt(&plaintext).unwrap();
        let recovered = cell.decrypt(&ciphertext).unwrap();

        assert_eq!(recovered, plaintext);

        assert_eq!(plaintext.len(), ciphertext.len());
    }

    #[test]
    fn empty_context() {
        let cell = SecureCell::with_key(b"deep secret").context_imprint();

        let plaintext = b"example plaintext";
        let error = cell.encrypt(&plaintext).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidParameter);
    }

    #[test]
    fn invalid_key() {
        let cell1 = SecureCell::with_key_and_context(b"deep secret", b"123").context_imprint();
        let cell2 = SecureCell::with_key_and_context(b"DEEP SECRET", b"123").context_imprint();

        let plaintext = b"example plaintext";
        let ciphertext = cell1.encrypt(&plaintext).unwrap();
        let recovered = cell2.decrypt(&ciphertext).unwrap();

        assert_ne!(recovered, plaintext);
    }

    #[test]
    fn invalid_context() {
        let cell1 = SecureCell::with_key_and_context(b"deep secret", b"123").context_imprint();
        let cell2 = SecureCell::with_key_and_context(b"deep secret", b"456").context_imprint();

        let plaintext = b"example plaintext";
        let ciphertext = cell1.encrypt(&plaintext).unwrap();
        let recovered = cell2.decrypt(&ciphertext).unwrap();

        assert_ne!(recovered, plaintext);
    }

    #[test]
    fn corrupted_data() {
        let cell = SecureCell::with_key_and_context(b"deep secret", b"123").context_imprint();

        let plaintext = b"example plaintext";
        let mut ciphertext = cell.encrypt(&plaintext).unwrap();
        ciphertext[10] = 42;
        let recovered = cell.decrypt(&ciphertext).unwrap();

        assert_ne!(recovered, plaintext);
    }
}
