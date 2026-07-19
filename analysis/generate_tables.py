import pandas as pd
import os
import glob

RESULTS_DIR = 'results'
TABLES_DIR = os.path.join(RESULTS_DIR, 'tables')
os.makedirs(TABLES_DIR, exist_ok=True)

def generate_latex_table(csv_path, output_name, caption, label):
    if not os.path.exists(csv_path):
        print(f"Warning: {csv_path} not found.")
        return
        
    df = pd.read_csv(csv_path)
    
    # Format numeric columns for presentation
    if 'Average(us)' in df.columns:
        df['Average(us)'] = df['Average(us)'].round(2)
    if 'StdDev(us)' in df.columns:
        df['StdDev(us)'] = df['StdDev(us)'].round(2)
    if 'OpsPerSecond' in df.columns:
        df['OpsPerSecond'] = df['OpsPerSecond'].round(2)
    if 'RelativeSlowdown' in df.columns:
        df['RelativeSlowdown'] = df['RelativeSlowdown'].round(2)
        
    # Select columns of interest for the academic table
    cols = ['Algorithm', 'Operation', 'Average(us)', 'StdDev(us)', 'OpsPerSecond', 'RelativeSlowdown']
    # Filter to only existing columns
    cols = [c for c in cols if c in df.columns]
    
    table_df = df[cols].copy()
    
    # Rename columns to be human readable
    rename_map = {
        'Algorithm': 'Algorithm',
        'Operation': 'Operation',
        'Average(us)': 'Mean Latency ($\\mu$s)',
        'StdDev(us)': 'Std Dev ($\\mu$s)',
        'OpsPerSecond': 'Ops/sec',
        'RelativeSlowdown': 'Slowdown (x)'
    }
    table_df.rename(columns=rename_map, inplace=True)
    
    latex_str = table_df.to_latex(index=False, caption=caption, label=label, 
                                  column_format='l' + 'c' * (len(cols)-1),
                                  float_format="%.2f")
                                  
    out_path = os.path.join(TABLES_DIR, output_name)
    with open(out_path, 'w') as f:
        f.write(latex_str)
    print(f"Generated {output_name}")

if __name__ == "__main__":
    print("Generating LaTeX tables...")
    
    generate_latex_table(
        os.path.join(RESULTS_DIR, 'ecdh_vs_mlkem_results.csv'),
        'table_exp1.tex',
        'Experiment 1: ECDH vs ML-KEM Performance',
        'tab:exp1'
    )
    
    generate_latex_table(
        os.path.join(RESULTS_DIR, 'rsa_vs_mldsa_results.csv'),
        'table_exp2.tex',
        'Experiment 2: RSA vs ML-DSA Performance',
        'tab:exp2'
    )
    
    generate_latex_table(
        os.path.join(RESULTS_DIR, 'secure_boot_results.csv'),
        'table_exp3.tex',
        'Experiment 3: Secure Boot Simulation (4MB Kernel)',
        'tab:exp3'
    )
    
    generate_latex_table(
        os.path.join(RESULTS_DIR, 'package_verify_results.csv'),
        'table_exp4.tex',
        'Experiment 4: Package Verification (Software Supply Chain)',
        'tab:exp4'
    )
    
    generate_latex_table(
        os.path.join(RESULTS_DIR, 'secure_ipc_results.csv'),
        'table_exp5.tex',
        'Experiment 5: Secure IPC Simulation (4KB Payload)',
        'tab:exp5'
    )
    
    print("All tables generated successfully.")
