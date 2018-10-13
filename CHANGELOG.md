[Unreleased]
============

The version currently under development.

## New features

- `SecureComparator` now implements `Default`.

## Breaking changes

- `SecureSessionState::Negotiate` enumeration variant is now properly spelled
  as `Negotiating` in order to be consistent with the core library.

- `gen_rsa_key_pair()`, `gen_ec_key_pair()`, `SecureComparator::new()` now
  return their results directly instead of wrapping errors into `Result` or
  `Option`. These functions may fail only on likely unrecoverable internal
  errors of Themis so now they simply panic in this case.

- `SecureSession::with_transport()` now returns `Result` instead of `Option`.

Version 0.0.1 — 2018-10-04
==========================

The first release of Themis for Rust.

- Full API coverage:
  * Key generation
  * Secure Cell
  * Secure Message
  * Secure Session
  * Secure Comparator
- Basic API documentation
- Basic test suite
- Basic code samples:
  * Key generation tool
  * File encryption using Secure Cell
  * Relay chat using Secure Message
