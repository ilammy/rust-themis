Here we keep tools for automated testing of Themis
across the supported platforms.
(Though, the tools are accessible to humans as well.)

- [**keygen**](keygen.rs) —
  a tool for generating ECDSA keys
  (usable by other [examples](../examples)) 
- <b>scell_*_string_echo</b> —
  encrypt or decrypt a string using Secure Cell
  - [**scell_context_string_echo**](scell_context_string_echo.rs) —
    sealing mode
  - [**scell_token_string_echo**](scell_token_string_echo.rs) —
    token protect mode
  - [**scell_context_string_echo**](scell_context_string_echo.rs) —
    context imprint mode

You can run a particular tool with Cargo like this:

```
$ cargo run --example keygen -- --help
keygen 0.0.2
Generating ECDSA key pairs.

USAGE:
    keygen [ARGS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <secret>    Secret key file (default: key)
    <public>    Public key file (default: key.pub)
```


## keygen

This tool can be used to generate key files usable by other examples.

Themis supports RSA keys for some use-cases,
but most of the features expect ECDSA keys.


## scell_*_string_echo

This is a family of command-line tools used for testing Secure Cell.

All of them accept plaintext input and produce base64-encoded encrypted output
(or vice versa for decryption).
The _user context_ can be provided as an optional last argument.

Token protect mode produces and accepts _two_ comma-separated strings:
the encrypted data followed by the authentication token:

```
$ cargo run --example scell_token_string_echo -- enc password input
KEYSbKY=,AAEBQAwAAAAQAAAABQAAAEPGcrB2ftqZT7fDEZYMS1ab3+iLGoOOAx/D3X4=

$ cargo run --example scell_token_string_echo -- dec password KEYSbKY=,AAEBQAwAAAAQAAAABQAAAEPGcrB2ftqZT7fDEZYMS1ab3+iLGoOOAx/D3X4=
input
```
