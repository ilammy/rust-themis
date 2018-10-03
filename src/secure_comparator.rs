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

use libc::{c_void, size_t, uint8_t};

use error::{themis_status_t, Error, ErrorKind};
use utils::into_raw_parts;

#[link(name = "themis")]
extern "C" {
    fn secure_comparator_create() -> *mut secure_comparator_t;

    fn secure_comparator_destroy(comp_ctx: *mut secure_comparator_t) -> themis_status_t;

    fn secure_comparator_append_secret(
        comp_ctx: *mut secure_comparator_t,
        secret_ptr: *const uint8_t,
        secret_len: size_t,
    ) -> themis_status_t;

    fn secure_comparator_begin_compare(
        comp_ctx: *mut secure_comparator_t,
        compare_data_ptr: *mut uint8_t,
        compare_data_len: *mut size_t,
    ) -> themis_status_t;

    fn secure_comparator_proceed_compare(
        comp_ctx: *mut secure_comparator_t,
        peer_compare_data_ptr: *const uint8_t,
        peer_compare_data_len: size_t,
        compare_data_ptr: *mut uint8_t,
        compare_data_len: *mut size_t,
    ) -> themis_status_t;

    fn secure_comparator_get_result(comp_ctx: *const secure_comparator_t) -> themis_status_t;
}

#[allow(non_camel_case_types)]
type secure_comparator_t = c_void;

pub struct SecureComparator {
    comp_ctx: *mut secure_comparator_t,
}

impl SecureComparator {
    pub fn new() -> Option<Self> {
        let comp_ctx = unsafe { secure_comparator_create() };

        if comp_ctx.is_null() {
            return None;
        }

        Some(Self { comp_ctx })
    }

    pub fn append_secret<S: AsRef<[u8]>>(&mut self, secret: S) -> Result<(), Error> {
        let (secret_ptr, secret_len) = into_raw_parts(secret.as_ref());

        unsafe {
            let status = secure_comparator_append_secret(self.comp_ctx, secret_ptr, secret_len);
            let error = Error::from_compare_status(status);
            if error.kind() != ErrorKind::Success {
                return Err(error);
            }
        }

        Ok(())
    }

    pub fn begin_compare(&mut self) -> Result<Vec<u8>, Error> {
        let mut compare_data = Vec::new();
        let mut compare_data_len = 0;

        unsafe {
            let status = secure_comparator_begin_compare(
                self.comp_ctx,
                ptr::null_mut(),
                &mut compare_data_len,
            );
            let error = Error::from_compare_status(status);
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        compare_data.reserve(compare_data_len);

        unsafe {
            let status = secure_comparator_begin_compare(
                self.comp_ctx,
                compare_data.as_mut_ptr(),
                &mut compare_data_len,
            );
            let error = Error::from_compare_status(status);
            if error.kind() != ErrorKind::CompareSendOutputToPeer {
                return Err(error);
            }
            debug_assert!(compare_data_len <= compare_data.capacity());
            compare_data.set_len(compare_data_len);
        }

        Ok(compare_data)
    }

    pub fn proceed_compare<D: AsRef<[u8]>>(&mut self, peer_data: D) -> Result<Vec<u8>, Error> {
        let (peer_compare_data_ptr, peer_compare_data_len) = into_raw_parts(peer_data.as_ref());

        let mut compare_data = Vec::new();
        let mut compare_data_len = 0;

        unsafe {
            let status = secure_comparator_proceed_compare(
                self.comp_ctx,
                peer_compare_data_ptr,
                peer_compare_data_len,
                ptr::null_mut(),
                &mut compare_data_len,
            );
            let error = Error::from_compare_status(status);
            if error.kind() != ErrorKind::BufferTooSmall {
                return Err(error);
            }
        }

        compare_data.reserve(compare_data_len);

        unsafe {
            let status = secure_comparator_proceed_compare(
                self.comp_ctx,
                peer_compare_data_ptr,
                peer_compare_data_len,
                compare_data.as_mut_ptr(),
                &mut compare_data_len,
            );
            let error = Error::from_compare_status(status);
            match error.kind() {
                ErrorKind::CompareSendOutputToPeer => {}
                // TODO: signal that this does not need to be sent
                ErrorKind::Success => {}
                _ => {
                    return Err(error);
                }
            }
            debug_assert!(compare_data_len <= compare_data.capacity());
            compare_data.set_len(compare_data_len);
        }

        Ok(compare_data)
    }

    pub fn get_result(&self) -> Result<bool, Error> {
        let status = unsafe { secure_comparator_get_result(self.comp_ctx) };
        let error = Error::from_match_status(status);
        match error.kind() {
            ErrorKind::CompareMatch => Ok(true),
            ErrorKind::CompareNoMatch => Ok(false),
            _ => Err(error),
        }
    }
}

impl Drop for SecureComparator {
    fn drop(&mut self) {
        unsafe {
            let status = secure_comparator_destroy(self.comp_ctx);
            let error = Error::from_themis_status(status);
            if (cfg!(debug) || cfg!(test)) && error.kind() != ErrorKind::Success {
                panic!("secure_comparator_destroy() failed: {}", error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_matching_data() {
        let mut comparator1 = SecureComparator::new().unwrap();
        let mut comparator2 = SecureComparator::new().unwrap();

        comparator1.append_secret(b"se-e-ecrets").unwrap();
        comparator2.append_secret(b"se-e-ecrets").unwrap();

        let data = comparator1.begin_compare().unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let data = comparator1.proceed_compare(&data).unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let _ata = comparator1.proceed_compare(&data).unwrap();

        assert!(comparator1.get_result().unwrap());
        assert!(comparator2.get_result().unwrap());
    }

    #[test]
    fn compare_different_data() {
        let mut comparator1 = SecureComparator::new().unwrap();
        let mut comparator2 = SecureComparator::new().unwrap();

        comparator1
            .append_secret(b"far from the worn path of reason")
            .unwrap();
        comparator2
            .append_secret(b"further away from the sane")
            .unwrap();

        let data = comparator1.begin_compare().unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let data = comparator1.proceed_compare(&data).unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let _ata = comparator1.proceed_compare(&data).unwrap();

        assert!(!comparator1.get_result().unwrap());
        assert!(!comparator2.get_result().unwrap());
    }

    #[test]
    fn split_secrets() {
        let mut comparator1 = SecureComparator::new().unwrap();
        let mut comparator2 = SecureComparator::new().unwrap();

        comparator1.append_secret(b"123").unwrap();
        comparator1.append_secret(b"456").unwrap();
        comparator2.append_secret(b"123456").unwrap();

        let data = comparator1.begin_compare().unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let data = comparator1.proceed_compare(&data).unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let _ata = comparator1.proceed_compare(&data).unwrap();

        assert!(comparator1.get_result().unwrap());
        assert!(comparator2.get_result().unwrap());
    }

    #[test]
    fn simultaneous_start() {
        let mut comparator1 = SecureComparator::new().unwrap();
        let mut comparator2 = SecureComparator::new().unwrap();

        comparator1.append_secret(b"se-e-ecrets").unwrap();
        comparator2.append_secret(b"se-e-ecrets").unwrap();

        let data1 = comparator1.begin_compare().unwrap();
        let data2 = comparator2.begin_compare().unwrap();

        let error1 = comparator1.proceed_compare(&data2).unwrap_err();
        let error2 = comparator2.proceed_compare(&data1).unwrap_err();

        assert_eq!(error1.kind(), ErrorKind::InvalidParameter);
        assert_eq!(error2.kind(), ErrorKind::InvalidParameter);
    }

    // TODO: write some robust test for data corruption
    //
    // This one works, but the results are intermittent. Sometimes the comparisons don't match,
    // sometimes the comparators fail with 'invalid parameter' errors. Maybe we could make use
    // of some data fuzzing framework in the future.
    #[test]
    #[ignore]
    fn data_corruption() {
        let mut comparator1 = SecureComparator::new().unwrap();
        let mut comparator2 = SecureComparator::new().unwrap();

        comparator1.append_secret(b"se-e-ecrets").unwrap();
        comparator2.append_secret(b"se-e-ecrets").unwrap();

        let data = comparator1.begin_compare().unwrap();
        let mut data = comparator2.proceed_compare(&data).unwrap();
        data[20] = 42;
        let data = comparator1.proceed_compare(&data).unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let _ata = comparator1.proceed_compare(&data).unwrap();

        assert!(comparator1.get_result().unwrap());
        assert!(comparator2.get_result().unwrap());
    }

    #[test]
    fn reusing_comparators() {
        // TODO: avoid reusing comparators via a better API
        let mut comparator1 = SecureComparator::new().unwrap();
        let mut comparator2 = SecureComparator::new().unwrap();

        comparator1.append_secret(b"test").unwrap();
        comparator2.append_secret(b"data").unwrap();

        let data = comparator1.begin_compare().unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let data = comparator1.proceed_compare(&data).unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let _ata = comparator1.proceed_compare(&data).unwrap();

        assert!(!comparator1.get_result().unwrap());
        assert!(!comparator2.get_result().unwrap());

        comparator1.append_secret(b"same").unwrap();
        comparator2.append_secret(b"same").unwrap();

        let data = comparator1.begin_compare().unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let data = comparator1.proceed_compare(&data).unwrap();
        let data = comparator2.proceed_compare(&data).unwrap();
        let _ata = comparator1.proceed_compare(&data).unwrap();

        // Previous data is still appended and can't be unappended.
        assert!(!comparator1.get_result().unwrap());
        assert!(!comparator2.get_result().unwrap());
    }
}
