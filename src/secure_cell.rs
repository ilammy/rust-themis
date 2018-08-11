// Copyright 2018 ilammy
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
        message: *const uint8_t,
        message_length: size_t,
        plain_message: *mut uint8_t,
        plain_message_length: *mut size_t,
    ) -> themis_status_t;

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
        message: *const uint8_t,
        message_length: size_t,
        token: *const uint8_t,
        token_length: size_t,
        plain_message: *mut uint8_t,
        plain_message_length: *mut size_t,
    ) -> themis_status_t;
}

/// Encrypts `message` with `master_key` including optional `user_context` for verification.
pub fn encrypt_seal(
    master_key: &[u8],
    user_context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, i32> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (user_context_ptr, user_context_len) = into_raw_parts(user_context);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut encrypted_message = Vec::new();
    let mut encrypted_message_len = 0;

    unsafe {
        let status = themis_secure_cell_encrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut encrypted_message_len,
        );
        if status != 14 {
            return Err(status);
        }
    }

    encrypted_message.reserve(encrypted_message_len as usize);

    unsafe {
        let status = themis_secure_cell_encrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            encrypted_message.as_mut_ptr(),
            &mut encrypted_message_len,
        );
        if status != 0 {
            return Err(status);
        }
        debug_assert!(encrypted_message_len <= encrypted_message.capacity());
        encrypted_message.set_len(encrypted_message_len as usize);
    }

    Ok(encrypted_message)
}

/// Decrypts `message` with `master_key` and verifies authenticity of `user_context`.
pub fn decrypt_seal(
    master_key: &[u8],
    user_context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, i32> {
    let (master_key_ptr, master_key_len) = into_raw_parts(master_key);
    let (user_context_ptr, user_context_len) = into_raw_parts(user_context);
    let (message_ptr, message_len) = into_raw_parts(message);

    let mut decrypted_message = Vec::new();
    let mut decrypted_message_len = 0;

    unsafe {
        let status = themis_secure_cell_decrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            ptr::null_mut(),
            &mut decrypted_message_len,
        );
        if status != 14 {
            return Err(status);
        }
    }

    decrypted_message.reserve(decrypted_message_len as usize);

    unsafe {
        let status = themis_secure_cell_decrypt_seal(
            master_key_ptr,
            master_key_len,
            user_context_ptr,
            user_context_len,
            message_ptr,
            message_len,
            decrypted_message.as_mut_ptr(),
            &mut decrypted_message_len,
        );
        if status != 0 {
            return Err(status);
        }
        debug_assert!(decrypted_message_len <= decrypted_message.capacity());
        decrypted_message.set_len(decrypted_message_len as usize);
    }

    Ok(decrypted_message)
}

/// Encrypts `message` with `master_key` including optional `user_context` for verification.
/// Returns `(ciphertext, auth_token)` tuple.
pub fn encrypt_token_protect(
    master_key: &[u8],
    user_context: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), i32> {
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
        if status != 14 {
            return Err(status);
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
        if status != 0 {
            return Err(status);
        }
        debug_assert!(token_len <= token.capacity());
        token.set_len(token_len as usize);
        debug_assert!(encrypted_message_len <= encrypted_message.capacity());
        encrypted_message.set_len(encrypted_message_len as usize);
    }

    Ok((encrypted_message, token))
}

/// Decrypts `message` with `master_key` and `token` verifying `user_context`.
pub fn decrypt_token_protect(
    master_key: &[u8],
    user_context: &[u8],
    message: &[u8],
    token: &[u8],
) -> Result<Vec<u8>, i32> {
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
        if status != 14 {
            return Err(status);
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
        if status != 0 {
            return Err(status);
        }
        debug_assert!(decrypted_message_len <= decrypted_message.capacity());
        decrypted_message.set_len(decrypted_message_len as usize);
    }

    Ok(decrypted_message)
}

fn into_raw_parts(slice: &[u8]) -> (*const uint8_t, size_t) {
    (slice.as_ptr(), slice.len() as size_t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_seal_happy_path() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let ciphertext = encrypt_seal(password, &[], plaintext).unwrap();
        let recovered = decrypt_seal(password, &[], &ciphertext).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn mode_seal_invalid_key() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";
        let invalid = b"DEEP SECRET";

        let ciphertext = encrypt_seal(password, &[], plaintext).unwrap();
        let error = decrypt_seal(invalid, &[], &ciphertext).unwrap_err();

        assert_eq!(error, 11);
    }

    #[test]
    fn mode_seal_invalid_context() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let ciphertext = encrypt_seal(password, b"ctx1", plaintext).unwrap();
        let error = decrypt_seal(password, b"ctx2", &ciphertext).unwrap_err();

        assert_eq!(error, 11);
    }

    #[test]
    fn mode_seal_corrupted_data() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let mut ciphertext = encrypt_seal(password, &[], plaintext).unwrap();
        ciphertext[10] = 42;
        let error = decrypt_seal(password, &[], &ciphertext).unwrap_err();

        assert_eq!(error, 12);
    }

    #[test]
    fn mode_token_protect_happy_path() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let (ciphertext, token) = encrypt_token_protect(password, &[], plaintext).unwrap();
        let recovered = decrypt_token_protect(password, &[], &ciphertext, &token).unwrap();

        assert_eq!(recovered, plaintext);

        assert_eq!(plaintext.len(), ciphertext.len());
    }

    #[test]
    fn mode_token_protect_invalid_key() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";
        let invalid = b"DEEP SECRET";

        let (ciphertext, token) = encrypt_token_protect(password, &[], plaintext).unwrap();
        let error = decrypt_token_protect(invalid, &[], &ciphertext, &token).unwrap_err();

        assert_eq!(error, 11);
    }

    #[test]
    fn mode_token_protect_invalid_context() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let (ciphertext, token) = encrypt_token_protect(password, b"123", plaintext).unwrap();
        let error = decrypt_token_protect(password, b"456", &ciphertext, &token).unwrap_err();

        assert_eq!(error, 11);
    }

    #[test]
    fn mode_token_protect_corrupted_data() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let (mut ciphertext, token) = encrypt_token_protect(password, &[], plaintext).unwrap();
        ciphertext[10] = 42;
        let error = decrypt_token_protect(password, &[], &ciphertext, &token).unwrap_err();

        assert_eq!(error, 11);
    }

    #[test]
    fn mode_token_protect_corrupted_token() {
        let plaintext = b"example plaintext";
        let password = b"deep secret";

        let (ciphertext, mut token) = encrypt_token_protect(password, &[], plaintext).unwrap();
        token[10] = 42;
        let error = decrypt_token_protect(password, &[], &ciphertext, &token).unwrap_err();

        assert_eq!(error, 12);
    }
}
