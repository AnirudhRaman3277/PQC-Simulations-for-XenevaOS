#!/bin/bash

# Navigate to the root directory
cd "$(dirname "$0")"

echo "============================================================"
echo " Starting PQC Benchmark Suite - Stage 1 (C++ Execution)"
echo "============================================================"

# Ensure everything is built with the highest optimizations
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release_O3
make -j$(nproc)
cd ..

echo -e "\n--- Running Experiment 1: ECDH vs ML-KEM ---"
./build/bin/bench_ecdh_vs_mlkem

echo -e "\n--- Running Experiment 2: RSA vs ML-DSA ---"
./build/bin/bench_rsa_vs_mldsa

echo -e "\n--- Running Experiment 3: Secure Boot ---"
./build/bin/bench_secure_boot

echo -e "\n--- Running Experiment 4: Package Verify ---"
./build/bin/bench_package_verify

echo -e "\n--- Running Experiment 5: Secure IPC ---"
./build/bin/bench_secure_ipc

echo -e "\n"
# Now run the Python analysis pipeline (Stage 2)
./analysis/run_pipeline.sh
