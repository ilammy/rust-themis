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

#[macro_use]
extern crate clap;
extern crate themis;

use std::fs::OpenOptions;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use themis::keygen::gen_ec_key_pair;

fn main() {
    let matches = clap_app!(keygen =>
        (version: env!("CARGO_PKG_VERSION"))
        (about: "Generating ECDSA key pairs.")
        (@arg secret: "Secret key file (default: key)")
        (@arg public: "Public key file (default: key.pub)")
    )
    .get_matches();
    let secret_path = matches.value_of("secret").unwrap_or("key");
    let public_path = matches.value_of("public").unwrap_or("key.pub");

    let (secret_key, public_key) = gen_ec_key_pair().split();

    match write_file(&secret_key, &secret_path, 0o400) {
        Ok(_) => eprintln!("wrote secret key to {}", secret_path),
        Err(e) => eprintln!("failed to write secret key to {}: {}", secret_path, e),
    }
    match write_file(&public_key, &public_path, 0o666) {
        Ok(_) => eprintln!("wrote public key to {}", public_path),
        Err(e) => eprintln!("failed to write public key to {}: {}", public_path, e),
    }
}

fn write_file<K: AsRef<[u8]>>(key: K, path: &str, mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true);
    options.truncate(true);
    options.write(true);
    #[cfg(unix)]
    options.mode(mode);

    let mut file = options.open(path)?;
    file.write_all(key.as_ref())?;
    Ok(())
}