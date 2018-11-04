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
extern crate cc;

use std::collections::HashSet;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn main() {
    let (include_dir, lib_dir, libs) = get_themis();
    let linkage = select_linkage(&lib_dir, &libs);

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:include={}", include_dir.display());
    for lib in libs {
        println!("cargo:rustc-link-lib={}={}", linkage, lib);
    }

    let whitelist = "(THEMIS|themis|secure_(comparator|session)|STATE)_.*";
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", include_dir.display()))
        .header("src/wrapper.h")
        .whitelist_function(whitelist)
        .whitelist_type(whitelist)
        .whitelist_var(whitelist)
        .rustified_enum("themis_key_kind")
        .generate()
        .expect("generating bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("writing bindings!");

    cc::Build::new()
        .file("src/wrapper.c")
        .include("src")
        .include(&include_dir)
        .compile("themis_shims");
}

fn env_var(name: &str) -> Option<OsString> {
    println!("cargo:rerun-if-env-changed={}", name);
    env::var_os(name)
}

/// Embarks on an incredible adventure and returns with an include directory, library directory,
/// and a list of Themis libraries.
fn get_themis() -> (PathBuf, PathBuf, Vec<String>) {
    None.or_else(|| probe_environment())
        .or_else(|| probe_homebrew())
        .or_else(|| probe_pkg_config())
        .or_else(|| probe_standard_locations())
        .expect(&format!(
            "

`libthemis-sys` could not find Themis installation in your system.

Please make sure you have appropriate development package installed.
On Linux it's called `libthemis-dev`, not just `libthemis`.
On macOS Homebrew formula is called `themis` or `themis-openssl`.

Please refer to the documentation for installation instructions:

    https://github.com/cossacklabs/themis#quickstart

This crate can use `pkg-config` and `brew` to locate the library.
You may help it by installing these tools and making sure that
they are correctly configured.

If you are sure that the library is installed in the system
but this crate still fails to locate it then you can help it
by setting the following environment variables: THEMIS_DIR,
THEMIS_INCLUDE_DIR, THEMIS_LIB_DIR and trying again.

"
        ))
}

/// Checks environment overrides for Themis locations.
fn probe_environment() -> Option<(PathBuf, PathBuf, Vec<String>)> {
    // TODO: implement
    None
}

/// Tries asking Homebrew for directions if available.
fn probe_homebrew() -> Option<(PathBuf, PathBuf, Vec<String>)> {
    // TODO: implement
    None
}

/// Tries asking pkg-config for directions if available.
fn probe_pkg_config() -> Option<(PathBuf, PathBuf, Vec<String>)> {
    // TODO: implement
    None
}

/// Makes a last-ditch effort with an educated guess and looks for Themis at standard locations.
fn probe_standard_locations() -> Option<(PathBuf, PathBuf, Vec<String>)> {
    None.or_else(|| probe_location("/usr/local/include", "/usr/local/lib"))
        .or_else(|| probe_location("/usr/include", "/usr/lib"))
}

fn probe_location(include_dir: &str, lib_dir: &str) -> Option<(PathBuf, PathBuf, Vec<String>)> {
    fn exists_in<P: AsRef<Path>, F: Fn(&Path) -> bool>(path: P, predicate: F) -> bool {
        if let Ok(files) = path.as_ref().read_dir() {
            files
                .filter_map(|e| e.ok().map(|e| e.path()))
                .any(|path| predicate(&path))
        } else {
            false
        }
    }

    fn like_library(path: &Path, substr: &str) -> bool {
        let prefix = format!("lib{}", substr);
        path.file_name()
            .and_then(|s| s.to_str())
            .map_or(false, |name| name.starts_with(&prefix))
    }

    let include_dir = PathBuf::from(include_dir);
    let lib_dir = PathBuf::from(lib_dir);
    let libs = vec!["themis".to_owned(), "soter".to_owned()];

    if !include_dir.join("themis/themis.h").exists() {
        return None;
    }
    if !include_dir.join("soter/soter.h").exists() {
        return None;
    }
    if !exists_in(&lib_dir, |f| like_library(f, "themis")) {
        return None;
    }
    if !exists_in(&lib_dir, |f| like_library(f, "soter")) {
        return None;
    }

    Some((include_dir, lib_dir, libs))
}

/// Decides whether we should link available libraries statically or dynamically.
fn select_linkage(lib_dir: &PathBuf, libs: &Vec<String>) -> &'static str {
    // First check for explicit instructions.
    if let Some(linkage) = env_var("THEMIS_STATIC").and_then(|s| s.into_string().ok()) {
        return if linkage == "0" { "dylib" } else { "static" };
    }

    // Now see what files we actually have available in the library directory
    // which look like our libraries.
    let files = lib_dir
        .read_dir()
        .expect(&format!("Themis library directory: {}", lib_dir.display()))
        .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
        .filter(|filename| libs.iter().any(|lib| filename.contains(lib)))
        .collect::<HashSet<_>>();

    // Then check whether there is a full set of static or dynamic libraries available.
    let can_static = libs.iter().all(|lib| {
        let static_lib = format!("lib{}.a", lib);
        files.contains(&static_lib)
    });
    let can_dylib = libs.iter().all(|lib| {
        let dylib_macos = format!("lib{}.dylib", lib);
        let dylib_linux = format!("lib{}.so", lib);
        files.contains(&dylib_macos) || files.contains(&dylib_linux)
    });

    // And finally make a decision based on the intelligence we've gathered.
    match (can_static, can_dylib) {
        (true, false) => "static",
        (false, true) => "dylib",

        (false, false) => panic!(
            "Themis library directory {} missing suitable libraries",
            lib_dir.display()
        ),

        // If we have either static or dynamic libraries available then prefer dynamic linkage
        // because this is a cryptographic library which could benefit from security upgrades.
        (true, true) => "dylib",
    }
}
