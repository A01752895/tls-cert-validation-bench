# Methodology

## Protocol
TLS 1.3

## Authentication Model
X.509 server certificate authentication.

## Independent Variables
- Signature scheme:
  - RSA-2048
  - RSA-3072
  - ECDSA P-256
  - ECDSA P-384
- Chain length:
  - 1 to 5 certificates sent by the server

## Dependent Variables
- Pure X.509 validation latency
- TLS handshake latency
- TLS handshake throughput
- Total DER size of transmitted chain

## Operational Definition
`chain_len` is defined as the number of certificates transmitted by the server:
- 1 = leaf only
- 2 = leaf + 1 intermediate
- ...
The root CA is not transmitted and is instead used as the local trust anchor.

## Measurement Modes
1. Pure chain verification using OpenSSL verify
2. End-to-end TLS handshake measurement using OpenSSL s_server and Python ssl
3. Throughput under concurrency

## Environment
The default execution environment is localhost on Windows 10/11.
