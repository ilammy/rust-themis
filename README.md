# rust-themis

[![Build Status](https://travis-ci.org/ilammy/rust-themis.svg?branch=master)](https://travis-ci.org/ilammy/rust-themis)

Rust binding for [Themis] crypto library.

[Themis]: https://github.com/cossacklabs/themis

## Usage
 
First you need to install the native Themis library.
Please refer to [the quickstart guide] for installation instructions.

Then you simply add this to your Cargo.toml:

```toml
[dependencies]
themis = "0.0.1"
```

And you're ready to go.
You can start off experimenting with [the examples].

[the quickstart guide]: https://github.com/cossacklabs/themis/blob/master/README.md#quickstart
[the examples]: https://github.com/ilammy/rust-themis/tree/master/examples

## Building

This is a binding so it requires a native Themis library.
After that all the usual Cargo commands like `cargo test` should work out-of-the-box.

### Native Themis library

The easiest way to make native Themis available is to install it into your system.
Please refer to [the quickstart guide] for installation instructions for your platform.
Once that's done the build should complete successfully.

If the compilation fails with a message like this:

```
   Compiling libthemis-sys v0.0.1
error: failed to run custom build command for `libthemis-sys v0.0.1`
process didn't exit successfully: `/your/app/target/debug/build/libthemis-sys-caf961089016a618/build-script-build` (exit code: 101)
--- stdout
cargo:rerun-if-env-changed=THEMIS_INCLUDE_DIR
cargo:rerun-if-env-changed=THEMIS_LIB_DIR
cargo:rerun-if-env-changed=THEMIS_DIR

--- stderr
thread 'main' panicked at '

`libthemis-sys` could not find Themis installation in your system.

[ some lines omitted ]

', libcore/option.rs:1000:5
note: Run with `RUST_BACKTRACE=1` for a backtrace.
```

then read the message carefully and help the build find your library.

If you use a non-standard installation path
(e.g., `/opt/themis`)
then you can use the following environment variables
to point the build in the right direction:

- `THEMIS_DIR` —
  the directory prefix where you `make install` to.
  
  Setting this should be enough in most cases.
  If you do not use `make install`
  and copy the headers and binaries manually
  then set the following two variables instead.
 
- `THEMIS_INCLUDE_DIR` —
  path to include directory root
  (where `themis/themis.h` can be found).

- `THEMIS_LIB_DIR` —
  path to directory with library binaries
  (`libthemis.a`, `*.so`, `*.dylib`, etc.)

> ⚠️ **Static libraries do not work**
>
> Please note that static linkage to Themis is currently not supported.
> This _includes_ the vendored build described below. 

### Vendored build

It is also possible to use a built-in version of Themis instead of the one installed in your system.
This option can be enabled via Cargo's feature `vendored` in your Cargo.toml:

```toml
[dependencies]
themis = { version = "0.0.1", features = ["vendored"] }
```

This will pull Themis source code, compile it, and link to it statically.
Compiling built-in Themis requires the following dependencies to be present in the system:

- C and C++ compilers (gcc 4.8+, clang 3.5+)
- CMake 2.8.11+
- GNU make
- Go
- Perl 5.6.1+

These are build-time dependencies.
They are not required at run-time,
and `themis` crate will not have any 3rd-party dependencies.

If you want to build vendored Themis from a local git tree
(not from crates.io or from a distribution tarball)
then please initialize git submodules first with the following command: 

```console
git submodule update --init --recursive
```

## Licensing

The code is distributed under [Apache 2.0 license](LICENSE).
