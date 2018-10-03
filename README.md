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

Obviously, you will need to have native Themis library installed in order to do development.
See [_Usage_](#usage) for details.

After that all the usual Cargo commands like `cargo test` should work out-of-the-box.

## Licensing

The code is distributed under [Apache 2.0 license](LICENSE).
