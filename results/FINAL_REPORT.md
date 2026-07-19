# PQC Benchmark Suite for XenevaOS — Final Report

## System Information
- **Compiler:** GNU
- **OpenSSL:** OpenSSL 3.5.5 27 Jan 2026
- **CPU:** N/A
- **Kernel:** 6.18.33.2-microsoft-standard-WSL2
- **RAM:** 7.4Gi

## Experiment 1: ECDH P-256 vs ML-KEM-768
Key establishment benchmarking comparing classical Elliptic Curve Diffie-Hellman with Post-Quantum ML-KEM.

| Algorithm   | Compiler   | CompilerVersion                      | OptimizationFlags                  | CPUModel                               | OS    | Timestamp               | Operation         |   Iterations |   Average(us) |   Median(us) |   Minimum(us) |   Maximum(us) |   StdDev(us) |   CI95(us) |   OpsPerSecond |   RelativeSlowdown |   OverheadPct |
|:------------|:-----------|:-------------------------------------|:-----------------------------------|:---------------------------------------|:------|:------------------------|:------------------|-------------:|--------------:|-------------:|--------------:|--------------:|-------------:|-----------:|---------------:|-------------------:|--------------:|
| ECDH-P256   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Key Generation    |         5000 |         25.83 |        21.73 |         21.25 |        208.33 |        10.98 |       0.3  |       38720.5  |               1    |          0    |
| ECDH-P256   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Shared Secret     |         5000 |         80.96 |        72.43 |         72.09 |       2310.48 |        40.11 |       1.11 |       12352.2  |               1    |          0    |
| ECDH-P256   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Full Key Exchange |         5000 |        138.68 |       119.03 |        116.58 |       1459.56 |        50.31 |       1.39 |        7210.91 |               1    |          0    |
| ML-KEM-768  | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Key Generation    |         5000 |         70.55 |        63.2  |         61.84 |        493.18 |        19.75 |       0.55 |       14173.9  |               2.73 |        173.18 |
| ML-KEM-768  | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Encapsulation     |         5000 |         49.99 |        45.49 |         45.13 |        981.67 |        25.12 |       0.7  |       20003.9  |               1    |          0    |
| ML-KEM-768  | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Decapsulation     |         5000 |         73.83 |        67.21 |         66.8  |       2600.77 |        47.14 |       1.31 |       13545.2  |               1    |          0    |
| ML-KEM-768  | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:28 UTC | Full Key Exchange |         5000 |        202.77 |       177.63 |        175.85 |       4684.28 |        90.66 |       2.51 |        4931.71 |               1.46 |         46.22 |

![Plots](plots/exp1_ecdh_vs_mlkem.png)

## Experiment 2: RSA-2048 vs ML-DSA-65
Digital signature benchmarking comparing classical RSA with Post-Quantum ML-DSA.

| Algorithm   | Compiler   | CompilerVersion                      | OptimizationFlags                  | CPUModel                               | OS    | Timestamp               | Operation      |   Iterations |   Average(us) |   Median(us) |   Minimum(us) |   Maximum(us) |   StdDev(us) |   CI95(us) |   OpsPerSecond |   RelativeSlowdown |   OverheadPct |
|:------------|:-----------|:-------------------------------------|:-----------------------------------|:---------------------------------------|:------|:------------------------|:---------------|-------------:|--------------:|-------------:|--------------:|--------------:|-------------:|-----------:|---------------:|-------------------:|--------------:|
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:31 UTC | Key Generation |          100 |      53605.4  |     45354.4  |      13237.2  |     258376    |     36766.1  |    7206.15 |          18.65 |               1    |          0    |
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:31 UTC | Sign           |          100 |        757.34 |       797.05 |        602.26 |       1353.48 |       144.53 |      28.33 |        1320.41 |               1    |          0    |
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:31 UTC | Verify         |          100 |         19.73 |        19.51 |         19.45 |         37.51 |         1.84 |       0.36 |       50685.1  |               1    |          0    |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:31 UTC | Key Generation |          100 |        194.08 |       183.44 |        182.11 |        358.08 |        29.87 |       5.86 |        5152.6  |               0    |        -99.64 |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:31 UTC | Sign           |          100 |       1069.37 |       831.56 |        347.29 |       4755.34 |       778.61 |     152.61 |         935.13 |               1.41 |         41.2  |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:31 UTC | Verify         |          100 |        209.89 |       184.54 |        183.54 |        767.09 |        70.15 |      13.75 |        4764.3  |              10.64 |        963.85 |

![Plots](plots/exp2_rsa_vs_mldsa.png)

## Experiment 3: Secure Boot Simulation
Simulating verification latency during kernel boot for a 4MB payload.

| Algorithm   | Compiler   | CompilerVersion                      | OptimizationFlags                  | CPUModel                               | OS    | Timestamp               | Operation         |   Iterations |   Average(us) |   Median(us) |   Minimum(us) |   Maximum(us) |   StdDev(us) |   CI95(us) |   OpsPerSecond |   RelativeSlowdown |   OverheadPct |
|:------------|:-----------|:-------------------------------------|:-----------------------------------|:---------------------------------------|:------|:------------------------|:------------------|-------------:|--------------:|-------------:|--------------:|--------------:|-------------:|-----------:|---------------:|-------------------:|--------------:|
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:43 UTC | Boot Verification |         1000 |       2593.26 |      2525.86 |       2484.01 |       4055.66 |       187.51 |      11.62 |         385.61 |               1    |          0    |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:43 UTC | Boot Verification |         1000 |       9883.74 |      9635.1  |       9192.09 |      17401.9  |       905.05 |      56.1  |         101.18 |               3.81 |        281.13 |

![Plots](plots/exp3_secure_boot.png)

## Experiment 4: Package Verification
Simulating software supply chain batch verification (100, 500, 1000 packages of 1MB each).

| Algorithm   | Compiler   | CompilerVersion                      | OptimizationFlags                  | CPUModel                               | OS    | Timestamp               | Operation            |   Iterations |      Average(us) |       Median(us) |      Minimum(us) |      Maximum(us) |   StdDev(us) |   CI95(us) |   OpsPerSecond |   RelativeSlowdown |   OverheadPct |
|:------------|:-----------|:-------------------------------------|:-----------------------------------|:---------------------------------------|:------|:------------------------|:---------------------|-------------:|-----------------:|-----------------:|-----------------:|-----------------:|-------------:|-----------:|---------------:|-------------------:|--------------:|
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:57 UTC | Verify 100 Packages  |           10 |  66444.6         |  66302.3         |  64720.3         |  68580.2         |      1340.51 |     830.86 |          15.05 |               1    |          0    |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:57 UTC | Verify 100 Packages  |           10 | 269048           | 269216           | 260856           | 277332           |      5582.31 |    3459.95 |           3.72 |               4.05 |        304.92 |
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:57 UTC | Verify 500 Packages  |           10 | 333773           | 333147           | 331094           | 338707           |      2178.25 |    1350.09 |           3    |               1    |          0    |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:57 UTC | Verify 500 Packages  |           10 |      1.3577e+06  |      1.34466e+06 |      1.33359e+06 |      1.4668e+06  |     39507.7  |   24487.1  |           0.74 |               4.07 |        306.77 |
| RSA-2048    | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:57 UTC | Verify 1000 Packages |           10 | 663680           | 664467           | 654671           | 675353           |      5607.33 |    3475.46 |           1.51 |               1    |          0    |
| ML-DSA-65   | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:20:57 UTC | Verify 1000 Packages |           10 |      2.70894e+06 |      2.68677e+06 |      2.66186e+06 |      2.89256e+06 |     67405.1  |   41778.1  |           0.37 |               4.08 |        308.17 |

![Plots](plots/exp4_package_verify.png)

## Experiment 5: Secure IPC Simulation
Simulating round-trip secure message passing (Keygen -> KDF -> AES Encrypt/Decrypt) on a 4KB payload.

| Algorithm            | Compiler   | CompilerVersion                      | OptimizationFlags                  | CPUModel                               | OS    | Timestamp               | Operation     |   Iterations |   Average(us) |   Median(us) |   Minimum(us) |   Maximum(us) |   StdDev(us) |   CI95(us) |   OpsPerSecond |   RelativeSlowdown |   OverheadPct |
|:---------------------|:-----------|:-------------------------------------|:-----------------------------------|:---------------------------------------|:------|:------------------------|:--------------|-------------:|--------------:|-------------:|--------------:|--------------:|-------------:|-----------:|---------------:|-------------------:|--------------:|
| Classical (ECDH+AES) | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:22:02 UTC | IPC Roundtrip |         5000 |        177.27 |       153.08 |        146.81 |       3325.74 |        78.71 |       2.18 |        5641.02 |               1    |          0    |
| PQ (ML-KEM+AES)      | GNU        | g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0 | -march=native -fomit-frame-pointer | AMD Ryzen 7 5800H with Radeon Graphics | Linux | 2026-07-19 09:22:02 UTC | IPC Roundtrip |         5000 |        154.03 |       137.31 |        136.05 |       4331.22 |        98.25 |       2.72 |        6492.05 |               0.87 |        -13.11 |

![Plots](plots/exp5_secure_ipc.png)

---
*Report automatically generated by Stage 2 Python Analysis Pipeline.*
