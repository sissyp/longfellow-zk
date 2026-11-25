# Longfellow DOB-Only Zero-Knowledge Proofs

## Overview

Experimental extension of Longfellow providing privacy-preserving
date-of-birth interval verification for ISO mDL credentials.

The holder proves that an issuer-authenticated birth_date lies within
two public, inclusive date bounds without revealing the actual DOB.

## Implementation

- DOB interval proof statement.
- Authentication of the birth_date through issuer-signed mDL data.
- Prover and verifier support for the public interval.
- Compiled version 8 DOB circuit.
- Tests for accepted and rejected DOB intervals.

## Circuit specification

- Version: 8
- Number of attributes: 1
- Block encoding hash: 5264
- Block encoding signature: 4445
- Circuit hash: b603047bcc80a2cc2d4e7932852a60b41134ae87dfe10290655c4d6591c88926

## Multipaz integration

The associated multipaz-dob repository provides:

- A Rust FFI wrapper.
- Kotlin bindings.
- Wallet proof generation.
- Verification integration.
- JVM integration tests.

## Limitations

This is an experimental DOB-only implementation, not a general
replacement for all Longfellow proof circuits.

Android integration, broader interoperability, and additional security
testing remain future work.

## Status

Research prototype. Not production-ready.
