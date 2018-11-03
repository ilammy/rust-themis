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
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("themis");
        let out_dir = self.out_dir.as_ref().expect("OUT_DIR not set");
        let build_dir = out_dir.join("build");
        let install_dir = out_dir.join("install");

        // Themis uses in-source build. Cargo requires build scripts to never write anything
        // outside of OUT_DIR so we just have to copy the source code there.

        if build_dir.exists() {
            fs::remove_dir_all(&build_dir).expect("rm -r themis/build");
        }
        if install_dir.exists() {
            fs::remove_dir_all(&install_dir).expect("rm -r themis/install");
        }

        copy_dir::copy_dir(&src_dir, &build_dir).expect("cp -r src build");
        fs::create_dir(&install_dir).expect("mkdir themis/install");

        let mut make = make_cmd::make();

        make.args(&["-C".as_ref(), build_dir.as_os_str()])
            .env("PREFIX", &install_dir)
            .arg("install");

        let status = make.status().expect("make");
        if !status.success() {
            panic!("{:?} failed: exit={}", make, status);
        }

        Artifacts {
            include_dir: install_dir.join("include"),
            lib_dir: install_dir.join("lib"),
            libs: vec!["themis".to_owned(), "soter".to_owned()],
        }
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

    #[test]
    fn build_and_install() {
        let temp_dir = tempfile::tempdir().expect("temporary directory");
        let artifacts = Build::new().out_dir(&temp_dir).build();
        assert!(artifacts.include_dir().join("themis/themis.h").exists());
        assert!(artifacts.lib_dir().read_dir().unwrap().count() > 0);
        assert!(!artifacts.libs.is_empty());
    }
}
