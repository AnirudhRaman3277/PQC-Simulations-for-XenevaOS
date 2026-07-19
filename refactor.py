import os

for root, _, files in os.walk('experiments'):
    for file in files:
        if file.endswith('.cpp') or file.endswith('.h'):
            path = os.path.join(root, file)
            with open(path, 'r') as f:
                content = f.read()
            
            new_content = content.replace('std::chrono::high_resolution_clock', 'BenchClock')
            new_content = new_content.replace('write_csv(results_dir + "/ecdh_vs_mlkem_results.csv", all_results);', 'write_csv(results_dir + "/ecdh_vs_mlkem_results.csv", all_results, sysinfo);')
            new_content = new_content.replace('write_csv(results_dir + "/secure_boot_results.csv", all_results);', 'write_csv(results_dir + "/secure_boot_results.csv", all_results, sysinfo);')
            new_content = new_content.replace('write_csv(results_dir + "/secure_ipc_results.csv", all_results);', 'write_csv(results_dir + "/secure_ipc_results.csv", all_results, sysinfo);')
            new_content = new_content.replace('write_csv(results_dir + "/package_verify_results.csv", all_results);', 'write_csv(results_dir + "/package_verify_results.csv", all_results, sysinfo);')
            new_content = new_content.replace('write_csv(results_dir + "/rsa_vs_mldsa_results.csv", all_results);', 'write_csv(results_dir + "/rsa_vs_mldsa_results.csv", all_results, sysinfo);')

            if content != new_content:
                with open(path, 'w') as f:
                    f.write(new_content)
                print(f"Refactored {path}")
