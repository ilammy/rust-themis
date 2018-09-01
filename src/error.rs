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

const THEMIS_SUCCESS: themis_status_t = 0;
const THEMIS_FAIL: themis_status_t = 11;
const THEMIS_INVALID_PARAMETER: themis_status_t = 12;
const THEMIS_NO_MEMORY: themis_status_t = 13;
const THEMIS_BUFFER_TOO_SMALL: themis_status_t = 14;
const THEMIS_DATA_CORRUPT: themis_status_t = 15;
const THEMIS_INVALID_SIGNATURE: themis_status_t = 16;
const THEMIS_NOT_SUPPORTED: themis_status_t = 17;
const THEMIS_SSESSION_SEND_OUTPUT_TO_PEER: themis_status_t = 1;
const THEMIS_SSESSION_KA_NOT_FINISHED: themis_status_t = 19;
const THEMIS_SSESSION_TRANSPORT_ERROR: themis_status_t = 20;
const THEMIS_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR: themis_status_t = 21;

#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// Converts generic Themis status codes.
    pub(crate) fn from_themis_status(status: themis_status_t) -> Error {
        let kind = match status {
            THEMIS_SUCCESS => ErrorKind::Success,
            THEMIS_FAIL => ErrorKind::Fail,
            THEMIS_INVALID_PARAMETER => ErrorKind::InvalidParameter,
            THEMIS_NO_MEMORY => ErrorKind::NoMemory,
            THEMIS_BUFFER_TOO_SMALL => ErrorKind::BufferTooSmall,
            THEMIS_DATA_CORRUPT => ErrorKind::DataCorrupt,
            THEMIS_INVALID_SIGNATURE => ErrorKind::InvalidSignature,
            THEMIS_NOT_SUPPORTED => ErrorKind::NotSupported,
            other_status => ErrorKind::UnknownError(other_status),
        };
        Error { kind }
    }

    /// Converts status codes returned by Secure Session.
    pub(crate) fn from_session_status(status: themis_status_t) -> Error {
        let kind = match status {
            THEMIS_SSESSION_SEND_OUTPUT_TO_PEER => ErrorKind::SessionSendOutputToPeer,
            THEMIS_SSESSION_KA_NOT_FINISHED => ErrorKind::SessionKeyAgreementNotFinished,
            THEMIS_SSESSION_TRANSPORT_ERROR => ErrorKind::SessionTransportError,
            THEMIS_SSESSION_GET_PUB_FOR_ID_CALLBACK_ERROR => {
                ErrorKind::SessionGetPublicKeyForIdError
            }
            other_status => {
                return Error::from_themis_status(other_status);
            }
        };
        Error { kind }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::UnknownError(status) => write!(f, "unknown error: {}", status),
            ErrorKind::Success => write!(f, "success"),

            ErrorKind::Fail => write!(f, "failure"),
            ErrorKind::InvalidParameter => write!(f, "invalid parameter"),
            ErrorKind::NoMemory => write!(f, "out of memory"),
            ErrorKind::BufferTooSmall => write!(f, "buffer too small"),
            ErrorKind::DataCorrupt => write!(f, "corrupted data"),
            ErrorKind::InvalidSignature => write!(f, "invalid signature"),
            ErrorKind::NotSupported => write!(f, "operation not supported"),

            ErrorKind::SessionSendOutputToPeer => write!(f, "send key agreement data to peer"),
            ErrorKind::SessionKeyAgreementNotFinished => write!(f, "key agreement not finished"),
            ErrorKind::SessionTransportError => write!(f, "transport layer error"),
            ErrorKind::SessionGetPublicKeyForIdError => {
                write!(f, "failed to get public key for ID")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorKind {
    UnknownError(i32),
    Success,

    Fail,
    InvalidParameter,
    NoMemory,
    BufferTooSmall,
    DataCorrupt,
    InvalidSignature,
    NotSupported,

    SessionSendOutputToPeer,
    SessionKeyAgreementNotFinished,
    SessionTransportError,
    SessionGetPublicKeyForIdError,
}
