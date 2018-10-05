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

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let whitelist = "(THEMIS|themis|secure_(comparator|session)|STATE)_.*";
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .whitelist_function(whitelist)
        .whitelist_type(whitelist)
        .whitelist_var(whitelist)
        .generate()
        .expect("generating bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("writing bindings!");
}
