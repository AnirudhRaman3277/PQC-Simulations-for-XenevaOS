# PQC Simulations for XenevaOS

This repository contains the full source code for the Post-Quantum Cryptography (PQC) benchmarking framework designed for the development of XenevaOS. It serves as an empirical foundation to guide architectural decisions regarding the transition from classical cryptography (ECDH, RSA) to NIST-standardized post-quantum algorithms (ML-KEM, ML-DSA).

## Project Structure

- **`/experiments`**: Contains the C++ source code for five distinct benchmarking scenarios:
  1. `ecdh_vs_mlkem`: Key Session Establishment KEM benchmarking.
  2. `rsa_vs_mldsa`: Digital Signatures and Authentication benchmarking.
  3. `secure_boot`: Trusted Boot / Kernel Integrity Simulation (4 MB Kernel image).
  4. `package_verify`: Software Supply Chain package verification with variable batch sizes.
  5. `secure_ipc`: Secure Inter-Process Communication (IPC) Simulation payload exchange.
- **`/include`**: Core statistical tracking, system telemetry generation, and file exporting headers (`benchmark_common.h`).
- **`/analysis`**: Python pipeline used to parse CSV/JSON exports into plots, LaTeX tables, and Markdown reports.
- **`/results`**: Holds all output data, including CSV, JSON, logs, generated PDFs, and `FINAL_REPORT.md`.

## Prerequisites

### 1. C++ Build Environment
- CMake (>= 3.10)
- GCC or Clang (Clang++ is automatically preferred if available)
- OpenSSL (>= 3.0) with PQC algorithm support built-in

### 2. Python Environment
The analysis stage requires Python 3 with the following libraries:
- `pandas`
- `matplotlib`
- `tabulate` (for markdown generation)

It is recommended to run this inside a Conda environment.

## Getting Started

To completely build the C++ suite, run all 5 experiments, and trigger the data analysis pipeline, you only need to run one script:

```bash
./run_all.sh
```

### What `run_all.sh` does automatically:
1. **Compilation**: Creates a `build/` directory and compiles the framework via CMake using the `Release_O3` optimization profile (with `-march=native` and `-fomit-frame-pointer`).
2. **Benchmarking Execution**: Runs all five experimental binaries sequentially. High-resolution telemetry data is dumped directly to the `results/` folder.
3. **Data Analysis**: Triggers `./analysis/run_pipeline.sh` which sweeps through the output data, generating aesthetic matplotlib PDF charts, formatting raw data into presentation-ready LaTeX tables, and aggregating everything into `results/FINAL_REPORT.md`.

## Outputs

After a successful execution of the suite, navigate to the `results/` folder to inspect the output:
- **`FINAL_REPORT.md`**: A comprehensive, human-readable summary of all 5 experiments.
- **`plots/*.pdf`**: High-resolution performance charts visually mapping latency, throughput, and memory scaling.
- **`tables/*.tex`**: Formatted LaTeX code specifically optimized for research papers or technical reports.
- **Raw Data**: Granular CSV and JSON files per experiment detailing average, median, min, max, std-dev, and system hardware configuration (CPU cores, vendor, OpenSSL version, RAM).

## Key Architectural Findings
This framework successfully revealed crucial behavior of the PQC algorithms on modern hardware, notably:
- **ML-KEM (Key Encapsulation)**: Exhibits incredibly fast encapsulation phases (28 $\mu s$), easily outpacing classical ECDH after the initial key generation overhead.
- **ML-DSA (Digital Signatures)**: Exhibits astonishingly fast Key Generation compared to RSA-2048, but faces heavy structural bottlenecks during Verification operations ($9\times$ slower than RSA), requiring caching and parallelization subsystems inside XenevaOS.
