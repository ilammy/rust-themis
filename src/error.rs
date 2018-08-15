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

use std::{error, fmt};

use libc::int32_t;

#[allow(non_camel_case_types)]
pub(crate) type themis_status_t = int32_t;

#[derive(Debug)]
pub struct Error {
    status: themis_status_t,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        ErrorKind::from(self.status)
    }
}

#[doc(hidden)]
impl From<themis_status_t> for Error {
    fn from(status: themis_status_t) -> Error {
        Error { status }
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match ErrorKind::from(self.status) {
            ErrorKind::SendOutputToPeer => write!(f, "failed to send data to peer"),
            ErrorKind::Success => write!(f, "success"),
            ErrorKind::Fail => write!(f, "failure"),
            ErrorKind::InvalidParameter => write!(f, "invalid parameter"),
            ErrorKind::NoMemory => write!(f, "out of memory"),
            ErrorKind::BufferTooSmall => write!(f, "buffer too small"),
            ErrorKind::DataCorrupt => write!(f, "corrupted data"),
            ErrorKind::InvalidSignature => write!(f, "invalid signature"),
            ErrorKind::NotSupported => write!(f, "operation not supported"),
            ErrorKind::KeyAgreementNotFinished => write!(f, "key agreement not finished"),
            ErrorKind::TransportError => write!(f, "transport layer error"),
            ErrorKind::GetPublicKeyForIdError => write!(f, "failed to get public key for ID"),
            ErrorKind::UnknownError => write!(f, "unknown error: {}", self.status),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    UnknownError = -1,
    Success = 0,
    SendOutputToPeer = 1,
    Fail = 11,
    InvalidParameter = 12,
    NoMemory = 13,
    BufferTooSmall = 14,
    DataCorrupt = 15,
    InvalidSignature = 16,
    NotSupported = 17,
    KeyAgreementNotFinished = 19,
    TransportError = 20,
    GetPublicKeyForIdError = 21,
}

#[doc(hidden)]
impl From<themis_status_t> for ErrorKind {
    fn from(status: themis_status_t) -> Self {
        match status {
            0 => ErrorKind::Success,
            1 => ErrorKind::SendOutputToPeer,
            11 => ErrorKind::Fail,
            12 => ErrorKind::InvalidParameter,
            13 => ErrorKind::NoMemory,
            14 => ErrorKind::BufferTooSmall,
            15 => ErrorKind::DataCorrupt,
            16 => ErrorKind::InvalidSignature,
            17 => ErrorKind::NotSupported,
            19 => ErrorKind::KeyAgreementNotFinished,
            20 => ErrorKind::TransportError,
            21 => ErrorKind::GetPublicKeyForIdError,
            _ => ErrorKind::UnknownError,
        }
    }
}
