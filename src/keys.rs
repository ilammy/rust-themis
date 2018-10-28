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

//! Cryptographic keys.
//!
//! This module contains data structures for keys supported by Themis: RSA and ECDSA key pairs.

use error::{Error, ErrorKind, Result};

/// Key material.
#[derive(Clone)]
pub(crate) struct KeyBytes(Vec<u8>);

// TODO: securely zero memory when dropping KeyBytes (?)

impl KeyBytes {
    /// Makes a key from a copy of a byte slice.
    pub fn copy_slice(bytes: &[u8]) -> KeyBytes {
        KeyBytes(bytes.to_vec())
    }

    /// Makes an empty key.
    pub fn empty() -> KeyBytes {
        KeyBytes(Vec::new())
    }

    /// Returns key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//
// Key type definitions
//

/// RSA secret key.
#[derive(Clone)]
pub struct RsaSecretKey {
    inner: KeyBytes,
}

/// RSA public key.
#[derive(Clone)]
pub struct RsaPublicKey {
    inner: KeyBytes,
}

/// RSA key pair.
#[derive(Clone)]
pub struct RsaKeyPair {
    secret_key: KeyBytes,
    public_key: KeyBytes,
}

/// ECDSA secret key.
#[derive(Clone)]
pub struct EcdsaSecretKey {
    inner: KeyBytes,
}

/// ECDSA public key.
#[derive(Clone)]
pub struct EcdsaPublicKey {
    inner: KeyBytes,
}

/// ECDSA key pair.
#[derive(Clone)]
pub struct EcdsaKeyPair {
    secret_key: KeyBytes,
    public_key: KeyBytes,
}

/// A secret key.
///
/// This structure is used by cryptographic services which can support any type of key.
/// [`RsaSecretKey`] or [`EcdsaSecretKey`] can be turned into a `SecretKey` at no cost.
///
/// [`RsaSecretKey`]: struct.RsaSecretKey.html
/// [`EcdsaSecretKey`]: struct.EcdsaSecretKey.html
#[derive(Clone)]
pub struct SecretKey {
    inner: KeyBytes,
}

/// A public key.
///
/// This structure is used by cryptographic services which can support any type of key.
/// [`RsaPublicKey`] or [`EcdsaPublicKey`] can be turned into a `PublicKey` at no cost.
///
/// [`RsaPublicKey`]: struct.RsaPublicKey.html
/// [`EcdsaPublicKey`]: struct.EcdsaPublicKey.html
#[derive(Clone)]
pub struct PublicKey {
    inner: KeyBytes,
}

/// A pair of asymmetric keys.
///
/// This structure is used by cryptographic services which can support any type of key pair.
/// [`RsaKeyPair`] or [`EcdsaKeyPair`] can be turned into a `KeyPair` at no cost. A pair of
/// [`SecretKey`] and [`PublicKey`] can be joined into a `KeyPair` after a quick type check
/// if their types match (either RSA or ECDSA).
///
/// [`RsaKeyPair`]: struct.RsaKeyPair.html
/// [`EcdsaKeyPair`]: struct.EcdsaKeyPair.html
/// [`SecretKey`]: struct.SecretKey.html
/// [`PublicKey`]: struct.PublicKey.html
#[derive(Clone)]
pub struct KeyPair {
    secret_key: KeyBytes,
    public_key: KeyBytes,
}

/// Kind of an asymmetric key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyKind {
    /// RSA secret key.
    RsaSecret,
    /// RSA public key.
    RsaPublic,
    /// ECDSA secret key.
    EcdsaSecret,
    /// ECDSA public key.
    EcdsaPublic,
}

//
// Key pairs
//

impl RsaKeyPair {
    /// Splits this key pair into secret and public keys.
    pub fn split(self) -> (RsaSecretKey, RsaPublicKey) {
        (
            RsaSecretKey {
                inner: self.secret_key,
            },
            RsaPublicKey {
                inner: self.public_key,
            },
        )
    }

    /// Joins a pair of secret and public keys.
    ///
    /// Note that this method _does not_ verify that the keys match: i.e., that it is possible
    /// to use the secret key to decrypt data encrypted with the public key.
    pub fn join(secret_key: RsaSecretKey, public_key: RsaPublicKey) -> RsaKeyPair {
        RsaKeyPair {
            secret_key: secret_key.inner,
            public_key: public_key.inner,
        }
    }
}

impl EcdsaKeyPair {
    /// Splits this key pair into secret and public keys.
    pub fn split(self) -> (EcdsaSecretKey, EcdsaPublicKey) {
        (
            EcdsaSecretKey {
                inner: self.secret_key,
            },
            EcdsaPublicKey {
                inner: self.public_key,
            },
        )
    }

    /// Joins a pair of secret and public keys.
    ///
    /// Note that this method _does not_ verify that the keys match: i.e., that it is possible
    /// to use the secret key to decrypt data encrypted with the public key.
    pub fn join(secret_key: EcdsaSecretKey, public_key: EcdsaPublicKey) -> EcdsaKeyPair {
        EcdsaKeyPair {
            secret_key: secret_key.inner,
            public_key: public_key.inner,
        }
    }
}

impl KeyPair {
    /// Splits this key pair into secret and public keys.
    pub fn split(self) -> (SecretKey, PublicKey) {
        (
            SecretKey {
                inner: self.secret_key,
            },
            PublicKey {
                inner: self.public_key,
            },
        )
    }

    /// Joins a pair of secret and public keys.
    ///
    /// Note that this method _does not_ verify that the keys match: i.e., that it is possible
    /// to use the secret key to decrypt data encrypted with the public key.
    ///
    /// However, it does verify that _the types_ of the keys match: i.e., that they are both
    /// either RSA or ECDSA keys. An error is returned if that's not the case. You can check
    /// the type of the key beforehand via its `kind()` method.
    pub fn try_join(secret_key: SecretKey, public_key: PublicKey) -> Result<KeyPair> {
        match (secret_key.kind(), public_key.kind()) {
            (KeyKind::RsaSecret, KeyKind::RsaPublic) => {}
            (KeyKind::EcdsaSecret, KeyKind::EcdsaPublic) => {}
            _ => {
                return Err(Error::with_kind(ErrorKind::InvalidParameter));
            }
        }
        Ok(KeyPair {
            secret_key: secret_key.inner,
            public_key: public_key.inner,
        })
    }
}

//
// Individual keys
//

impl SecretKey {
    /// Retrieves actual type of the stored key.
    pub fn kind(&self) -> KeyKind {
        unimplemented!()
    }
}

impl PublicKey {
    /// Retrieves actual type of the stored key.
    pub fn kind(&self) -> KeyKind {
        unimplemented!()
    }
}

//
// AsRef<[u8]> casts
//

impl AsRef<[u8]> for RsaSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl AsRef<[u8]> for RsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl AsRef<[u8]> for EcdsaSecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl AsRef<[u8]> for EcdsaPublicKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

//
// From/Into conversions
//

impl From<RsaSecretKey> for SecretKey {
    fn from(secret_key: RsaSecretKey) -> SecretKey {
        SecretKey {
            inner: secret_key.inner,
        }
    }
}

impl From<RsaPublicKey> for PublicKey {
    fn from(public_key: RsaPublicKey) -> PublicKey {
        PublicKey {
            inner: public_key.inner,
        }
    }
}

impl From<EcdsaSecretKey> for SecretKey {
    fn from(secret_key: EcdsaSecretKey) -> SecretKey {
        SecretKey {
            inner: secret_key.inner,
        }
    }
}

impl From<EcdsaPublicKey> for PublicKey {
    fn from(public_key: EcdsaPublicKey) -> PublicKey {
        PublicKey {
            inner: public_key.inner,
        }
    }
}

impl From<RsaKeyPair> for KeyPair {
    fn from(key_pair: RsaKeyPair) -> KeyPair {
        KeyPair {
            secret_key: key_pair.secret_key,
            public_key: key_pair.public_key,
        }
    }
}

impl From<EcdsaKeyPair> for KeyPair {
    fn from(key_pair: EcdsaKeyPair) -> KeyPair {
        KeyPair {
            secret_key: key_pair.secret_key,
            public_key: key_pair.public_key,
        }
    }
}
