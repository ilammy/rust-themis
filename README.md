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
themis = "0.0.2"
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
   Compiling libthemis-sys v0.0.2
error: failed to run custom build command for `libthemis-sys v0.0.2`
process didn't exit successfully: `target/debug/build/libthemis-sys-caf961089016a618/build-script-build` (exit code: 101)
--- stdout
cargo:rerun-if-env-changed=LIBTHEMIS_NO_PKG_CONFIG

[ some lines omitted ]

cargo:rerun-if-env-changed=PKG_CONFIG_SYSROOT_DIR

--- stderr
thread 'main' panicked at '

`libthemis-sys` could not find Themis installation in your system.

[ some lines omitted ]

', libthemis-sys/build.rs:60:13
note: Run with `RUST_BACKTRACE=1` for a backtrace.
```

then please read the message carefully and help the build find your library.

We use **pkg-config** to locate the native Themis library.
Make sure you have this tool installed and correctly configured.
If you use a non-standard installation path
(e.g., `/opt/themis`)
then you need to set `PKG_CONFIG_PATH` environment variable
to the directory containing *.pc files
(e.g., `/opt/themis/lib/pkgconfig`).

### Tweaking the build

You can set other environment variables to control how pkg-config resolves native dependencies.

- `LIBTHEMIS_STATIC` — set to prefer static linking
- `LIBTHEMIS_DYNAMIC` — set to prefer dynamic linking

Refer to [the `pkg_config` documentation] for more information about available environment variables.

[the `pkg_config` documentation]: https://docs.rs/pkg-config/latest/pkg_config/

### 🍺 A note for Homebrew users 

If you install Themis via `brew` on macOS then it will be using Homebrew's OpenSSL libraries.
Homebrew does not install OpenSSL into default system location (it's _keg-only_).
That's because your system is likely to contain its own OpenSSL installation in default path
and Homebrew won't replace it to avoid accidental breakage. 

You need to tell pkg-config to use Homebrew's OpenSSL
by setting `PKG_CONFIG_PATH` to the keg location of OpenSSL used by Themis.
You can usually find out where it is with a spell like this:

```console
$ find $(brew --prefix $(brew deps themis-openssl)) -follow -type d -name pkgconfig
/usr/local/opt/openssl/lib/pkgconfig
```

### ⛑ Bundled *.pc files

Unfortunately, Themis packages currently do not include *.pc files for pkg-config.
You can use the ones bundled with this repository as a temporary measure.
Take a look into [`pkgconfig`](pkgconfig) directory:

- `pkgconfig/system/*.pc` —
  if you install Themis into `/usr/lib`
  (usually the case on Linux with package managers)
- `pkgconfig/local/*.pc` —
  if you install Themis into `/usr/local/lib`
  (usually the case on macOS or with `make install`)

Copy these files somewhere in your home directory, for example,
and tell pkg-config to use them:

```console
$ mkdir ~/pkgconfig
$ cp pkgconfig/usr/local/lib/pkgconfig/*.pc ~/pkgconfig/
$ export PKG_CONFIG_PATH=$HOME/pkgconfig
```

Multiple paths in `PKG_CONFIG_PATH` are separated with colons,
like this:

```console
$ export PKG_CONFIG_PATH=$HOME/pkgconfig:/usr/local/opt/openssl/lib/pkgconfig
```

## Licensing

The code is distributed under [Apache 2.0 license](LICENSE).
