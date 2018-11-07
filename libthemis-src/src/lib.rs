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

//! Building native Themis library.

extern crate copy_dir;
extern crate make_cmd;
#[cfg(test)]
extern crate tempfile;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A builder (literally!) for Themis, produces [`Artifacts`].
///
/// [`Artifacts`]: struct.Artifacts.html
#[derive(Default)]
pub struct Build {
    out_dir: Option<PathBuf>,
}

/// Artifacts resulting from a [`Build`].
///
/// [`Build`]: struct.Build.html
pub struct Artifacts {
    include_dir: PathBuf,
    lib_dir: PathBuf,
    libs: Vec<String>,
}

fn check_dependencies() {
    fn fails_to_run(terms: &[&str]) -> bool {
        Command::new(&terms[0])
            .args(&terms[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
    }

    if fails_to_run(&["cmake", "--version"]) {
        panic!(
            "

It seems your system does not have CMake installed. CMake is required
to build Themis from source.

Please install \"cmake\" package and try again.

        "
        );
    }
    if fails_to_run(&["make", "--version"]) {
        panic!(
            "

It seems your system does not have GNU make installed. Make is required
to build Themis from source.

Please install \"make\" or \"build-essential\" package and try again.

        "
        );
    }
    if fails_to_run(&["cc", "--version"]) {
        panic!(
            "

It seems your system does not have a C compiler installed. C compiler
is required to build Themis from source.

Please install \"clang\" (or \"gcc\" and \"g++\") package and try again.

        "
        );
    }
    if fails_to_run(&["go", "version"]) {
        panic!(
            "

It seems your system does not have Golang installed. Go is required
to build Themis from source.

Please install \"go\" or \"golang\" package and try again.

        "
        );
    }
}

impl Build {
    /// Prepares a new build.
    pub fn new() -> Build {
        Build {
            out_dir: env::var_os("OUT_DIR").map(|s| PathBuf::from(s).join("themis")),
        }
    }

    /// Overrides output directory. Use it if OUT_DIR environment variable is not set or you want
    /// to customize the output location.
    pub fn out_dir<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.out_dir = Some(path.as_ref().to_path_buf());
        self
    }

    /// Builds Themis, panics on any errors.
    pub fn build(&self) -> Artifacts {
        check_dependencies();

        let out_dir = self.out_dir.as_ref().expect("OUT_DIR not set");
        let themis_src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("themis");
        let themis_build_dir = out_dir.join("build");
        let themis_install_dir = out_dir.join("install");
        let ssl_src_dir = themis_src_dir.join("third_party/boringssl/src");
        let ssl_build_dir = out_dir.join("boringssl-build");
        let ssl_install_dir = out_dir.join("boringssl-install");

        // Themis uses in-source build. Cargo requires build scripts to never write anything
        // outside of OUT_DIR so we just have to copy the source code there.

        if !out_dir.exists() {
            fs::create_dir(&out_dir).expect("mkdir themis");
        }
        if themis_build_dir.exists() {
            fs::remove_dir_all(&themis_build_dir).expect("rm -r themis/build");
        }
        if themis_install_dir.exists() {
            fs::remove_dir_all(&themis_install_dir).expect("rm -r themis/install");
        }
        if ssl_build_dir.exists() {
            fs::remove_dir_all(&ssl_build_dir).expect("rm -r boringssl/build");
        }
        if ssl_install_dir.exists() {
            fs::remove_dir_all(&ssl_install_dir).expect("rm -r boringssl/install");
        }

        copy_dir::copy_dir(&themis_src_dir, &themis_build_dir).expect("cp -r src build");
        fs::create_dir(&themis_install_dir).expect("mkdir themis/install");
        fs::create_dir(&ssl_build_dir).expect("mkdir boringssl/build");
        fs::create_dir(&ssl_install_dir).expect("mkdir boringssl/install");

        // First we have to build vendored BoringSSL which will act as cryptographic engine
        // for Themis. There is no choice of the backend for the user. If you want a custom
        // build then do it yourself and point libthemis-sys to the resulting artifacts.
        // This crate produces Themis binary that depends only on the system C library.
        // BoringSSL uses CMake for configuration and Make for build.

        let build_type = if cfg!(debug) { "Debug" } else { "Release" };
        let mut boringssl_configure = Command::new("cmake");
        boringssl_configure
            .current_dir(&ssl_build_dir)
            .arg(format!("-DCMAKE_BUILD_TYPE={}", build_type))
            .arg(&ssl_src_dir);
        run(boringssl_configure, "BoringSSL configuration");

        let mut boringssl_build = make_cmd::make();
        boringssl_build
            .current_dir(&ssl_build_dir)
            .arg("crypto")
            .arg("decrepit")
            .arg("ssl");
        run(boringssl_build, "BoringSSL build");

        // It's so nice to have an "install" target available so that we don't have to figure out
        // what the build artifacts are and copy them manually. Thank you, Google! Great usability!

        copy_dir::copy_dir(ssl_src_dir.join("include"), ssl_install_dir.join("include"))
            .expect("install boringssl/include");
        fs::create_dir(ssl_install_dir.join("lib")).expect("mkdir boringssl/lib");
        fs::copy(
            ssl_build_dir.join("crypto/libcrypto.a"),
            ssl_install_dir.join("lib/libcrypto.a"),
        ).expect("install libcrypto.a");
        fs::copy(
            ssl_build_dir.join("decrepit/libdecrepit.a"),
            ssl_install_dir.join("lib/libdecrepit.a"),
        ).expect("install libdecrepit.a");
        fs::copy(
            ssl_build_dir.join("ssl/libssl.a"),
            ssl_install_dir.join("lib/libssl.a"),
        ).expect("install libssl.a");

        // Finally we can build Themis. Note that we explicitly instruct the build
        // to use our BoringSSL installation created on the previous step.

        let mut themis_build_and_install = make_cmd::make();
        themis_build_and_install
            .current_dir(&themis_build_dir)
            .env("PREFIX", &themis_install_dir)
            .env("ENGINE", "boringssl")
            .env("ENGINE_INCLUDE_PATH", ssl_install_dir.join("include"))
            .env("ENGINE_LIB_PATH", ssl_install_dir.join("lib"))
            .arg("install");
        if cfg!(debug) {
            themis_build_and_install.env("DEBUG", "1");
        } else {
            themis_build_and_install.env_remove("DEBUG");
        }
        run(themis_build_and_install, "Themis build & install");

        Artifacts {
            include_dir: themis_install_dir.join("include"),
            lib_dir: themis_install_dir.join("lib"),
            libs: vec!["themis".to_owned(), "soter".to_owned()],
        }
    }
}

fn run(mut command: Command, what: &str) {
    let status = command
        .status()
        .expect(&format!("failed to execute {}", what));
    if !status.success() {
        panic!("{} failed: {}", what, status);
    }
}

impl Artifacts {
    /// Directory with installed headers.
    pub fn include_dir(&self) -> &Path {
        &self.include_dir
    }

    /// Directory with installed libraries.
    pub fn lib_dir(&self) -> &Path {
        &self.lib_dir
    }

    /// Resulting library names that need to be linked.
    pub fn libs(&self) -> &[String] {
        &self.libs
    }

    /// Outputs `cargo:*` lines instructing Cargo to link against Themis.
    pub fn print_cargo_instructions(&self) {
        println!("cargo:rustc-link-search=native={}", self.lib_dir.display());
        for lib in &self.libs {
            println!("cargo:rustc-link-lib=static={}", lib);
        }
        println!("cargo:include={}", self.include_dir.display());
        println!("cargo:lib={}", self.lib_dir.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::ffi::OsStr;

    #[test]
    fn build_and_install() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let artifacts = Build::new().out_dir(&temp_dir).build();
        assert!(artifacts.include_dir().join("themis/themis.h").exists());
        assert!(artifacts.lib_dir().read_dir().unwrap().count() > 0);
        assert!(!artifacts.libs.is_empty());
    }

    #[test]
    #[allow(non_snake_case)]
    fn build_and_install_to_OUT_DIR() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let artifacts = with_env_var("OUT_DIR", temp_dir.path(), || Build::new().build());
        assert!(artifacts.include_dir().join("themis/themis.h").exists());
        assert!(artifacts.lib_dir().read_dir().unwrap().count() > 0);
        assert!(!artifacts.libs.is_empty());
    }

    fn with_env_var<K, V, F, T>(key: K, value: V, f: F) -> T
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
        F: FnOnce() -> T,
    {
        let old_value = env::var_os(&key);
        env::set_var(&key, value);
        let result = f();
        match old_value {
            Some(old_value) => env::set_var(&key, old_value),
            None => env::remove_var(&key),
        }
        result
    }
}
