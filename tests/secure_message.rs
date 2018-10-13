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

extern crate themis;

use themis::{
    keygen::{gen_ec_key_pair, gen_rsa_key_pair},
    secure_message::{SecureMessage, SecureSign, SecureVerify},
    ErrorKind,
};

#[test]
fn mode_encrypt_decrypt() {
    let (private, public) = gen_rsa_key_pair();
    let secure = SecureMessage::new(private, public);

    let plaintext = b"test message please ignore";
    let wrapped = secure.wrap(&plaintext).expect("encryption");
    let recovered_message = secure.unwrap(&wrapped).expect("decryption");

    assert_eq!(recovered_message, plaintext);
}

#[test]
fn mode_sign_verify() {
    let (private, public) = gen_rsa_key_pair();
    let sign = SecureSign::new(private);
    let verify = SecureVerify::new(public);

    let plaintext = b"test message please ignore";
    let signed_message = sign.sign(&plaintext).unwrap();
    let recovered_message = verify.verify(&signed_message).unwrap();

    assert_eq!(recovered_message, plaintext);
}

#[test]
fn invalid_key() {
    let (private1, public1) = gen_ec_key_pair();
    let (private2, public2) = gen_ec_key_pair();
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
    let (private, public) = gen_rsa_key_pair();
    // Note that key parameters are in wrong order.
    let secure = SecureMessage::new(public, private);

    let plaintext = b"test message please ignore";
    let wrapped = secure.wrap(&plaintext).expect("encryption");
    let error = secure.unwrap(&wrapped).expect_err("decryption error");

    assert_eq!(error.kind(), ErrorKind::InvalidParameter);
}

#[test]
fn corrupted_data() {
    let (private, public) = gen_rsa_key_pair();
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
