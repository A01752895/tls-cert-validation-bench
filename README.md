# TLS Certificate Validation Benchmark

Reproducible benchmark of the operational cost of validating X.509 certificates in TLS 1.3 under classical schemes (RSA vs ECDSA) and different chain lengths.

## Overview

This repository implements an experimental pipeline to study the impact of X.509 certificate–based authentication on:

- pure validation latency,
- total TLS handshake latency,
- total transmitted certificate chain size,
- and throughput under concurrency.

The project compares RSA and ECDSA variants with different chain lengths, treating certificate validation as a black box from the perspective of the TLS stack and OpenSSL.

## Research Question

What is the real operational cost of verifying digital certificates in TLS under different classical schemes (RSA vs ECDSA) and varying chain lengths?

## Objectives

1. Automatically generate RSA and ECDSA certificates.
2. Build controlled X.509 chains with different numbers of intermediate certificates.
3. Measure pure chain validation with OpenSSL.
4. Measure real TLS 1.3 handshakes with and without validation.
5. Measure throughput and scalability under different levels of concurrency.
6. Export results to CSV and generate comparative plots.

## Platform

This repository is prepared to run on **Windows 10/11** using:

- PowerShell
- Python 3
- OpenSSL
- Wireshark/TShark

## Quick Start (Windows)

Open **PowerShell** inside the repository folder and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\setup_windows.ps1
.\run_demo.ps1
