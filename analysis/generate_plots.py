import json
import os
import glob
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Apply basic styling for publication quality
plt.style.use('grayscale')
plt.rcParams.update({
    'font.size': 12,
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.autolayout': True,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'hatch.linewidth': 1.0
})

RESULTS_DIR = 'results'
PLOTS_DIR = os.path.join(RESULTS_DIR, 'plots')
os.makedirs(PLOTS_DIR, exist_ok=True)

def load_json_results(filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found.")
        return None
    with open(filepath, 'r') as f:
        return json.load(f)

def plot_bar_chart(title, xlabel, ylabel, categories, values_dict, filename):
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(categories))
    width = 0.35

    hatches = ['', '///']
    colors = ['#dddddd', '#666666']
    
    for idx, (label, values) in enumerate(values_dict.items()):
        offset = width * idx - width/2 + width/2 if len(values_dict) == 2 else 0
        if len(values_dict) > 2:
            offset = width * idx - width
            
        ax.bar(x + offset, values, width, label=label, color=colors[idx % len(colors)], 
               edgecolor='black', hatch=hatches[idx % len(hatches)])

    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xlabel(xlabel)
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()
    
    plt.savefig(os.path.join(PLOTS_DIR, filename), dpi=300, format='pdf')
    plt.savefig(os.path.join(PLOTS_DIR, filename.replace('.pdf', '.png')), dpi=300)
    plt.close()
    print(f"Generated {filename}")

def plot_experiment_1_and_2():
    # Exp 1: ECDH vs ML-KEM
    data1 = load_json_results('ecdh_vs_mlkem_results.json')
    if data1:
        res = data1['results']
        ops = ['Key Generation', 'Encapsulation', 'Decapsulation']
        
        # We need to map operations correctly as they might slightly differ in name
        ecdh_vals = []
        mlkem_vals = []
        
        for op in ops:
            ec_mean = next((r['average'] for r in res if r['algorithm'] == 'ECDH P-256' and op in r['operation']), 0)
            ml_mean = next((r['average'] for r in res if r['algorithm'] == 'ML-KEM-768' and op in r['operation']), 0)
            ecdh_vals.append(ec_mean)
            mlkem_vals.append(ml_mean)

        plot_bar_chart(
            'ECDH P-256 vs ML-KEM-768 (Latency)',
            'Operation', 'Latency (us)', ops,
            {'ECDH P-256': ecdh_vals, 'ML-KEM-768': mlkem_vals},
            'exp1_ecdh_vs_mlkem.pdf'
        )

    # Exp 2: RSA vs ML-DSA
    data2 = load_json_results('rsa_vs_mldsa_results.json')
    if data2:
        res = data2['results']
        ops = ['Key Generation', 'Sign', 'Verify']
        rsa_vals = []
        mldsa_vals = []
        
        for op in ops:
            rsa_mean = next((r['average'] for r in res if r['algorithm'] == 'RSA-2048' and op in r['operation']), 0)
            mld_mean = next((r['average'] for r in res if r['algorithm'] == 'ML-DSA-65' and op in r['operation']), 0)
            rsa_vals.append(rsa_mean)
            mldsa_vals.append(mld_mean)

        plot_bar_chart(
            'RSA-2048 vs ML-DSA-65 (Latency)',
            'Operation', 'Latency (us)', ops,
            {'RSA-2048': rsa_vals, 'ML-DSA-65': mldsa_vals},
            'exp2_rsa_vs_mldsa.pdf'
        )
        
        # Without Key Generation (since it skews the chart)
        plot_bar_chart(
            'RSA-2048 vs ML-DSA-65 (Sign/Verify only)',
            'Operation', 'Latency (us)', ['Sign', 'Verify'],
            {'RSA-2048': rsa_vals[1:], 'ML-DSA-65': mldsa_vals[1:]},
            'exp2_rsa_vs_mldsa_no_keygen.pdf'
        )

def plot_experiment_3():
    data = load_json_results('secure_boot_results.json')
    if not data: return
    
    res = data['results']
    rsa_mean = next((r['average'] / 1000.0 for r in res if r['algorithm'] == 'RSA-2048'), 0)
    mldsa_mean = next((r['average'] / 1000.0 for r in res if r['algorithm'] == 'ML-DSA-65'), 0)
    
    fig, ax = plt.subplots(figsize=(6, 5))
    categories = ['RSA-2048', 'ML-DSA-65']
    values = [rsa_mean, mldsa_mean]
    
    bars = ax.bar(categories, values, color=['#dddddd', '#666666'], edgecolor='black', hatch=['', '///'], width=0.5)
    ax.set_title('Secure Boot Simulation (4MB Kernel)')
    ax.set_ylabel('Verification Latency (ms)')
    
    # Add text labels on top of bars
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.2f} ms',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
                    
    plt.savefig(os.path.join(PLOTS_DIR, 'exp3_secure_boot.pdf'), dpi=300, format='pdf')
    plt.savefig(os.path.join(PLOTS_DIR, 'exp3_secure_boot.png'), dpi=300)
    plt.close()
    print("Generated exp3_secure_boot.pdf")

def plot_experiment_4():
    data = load_json_results('package_verify_results.json')
    if not data: return
    
    res = data['results']
    batches = [100, 500, 1000]
    rsa_times = []
    mldsa_times = []
    
    for b in batches:
        rsa = next((r['average'] / 1000.0 for r in res if r['algorithm'] == 'RSA-2048' and str(b) in r['operation']), 0)
        mldsa = next((r['average'] / 1000.0 for r in res if r['algorithm'] == 'ML-DSA-65' and str(b) in r['operation']), 0)
        rsa_times.append(rsa)
        mldsa_times.append(mldsa)
        
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(batches, rsa_times, marker='o', linestyle='-', color='black', label='RSA-2048')
    ax.plot(batches, mldsa_times, marker='s', linestyle='--', color='#555555', label='ML-DSA-65')
    
    ax.set_title('Package Verification Latency by Batch Size')
    ax.set_xlabel('Batch Size (Packages)')
    ax.set_ylabel('Total Verification Time (ms)')
    ax.legend()
    ax.set_xticks(batches)
    
    plt.savefig(os.path.join(PLOTS_DIR, 'exp4_package_verify.pdf'), dpi=300, format='pdf')
    plt.savefig(os.path.join(PLOTS_DIR, 'exp4_package_verify.png'), dpi=300)
    plt.close()
    print("Generated exp4_package_verify.pdf")

def plot_experiment_5():
    data = load_json_results('secure_ipc_results.json')
    if not data: return
    
    res = data['results']
    class_mean = next((r['average'] for r in res if 'Classical' in r['algorithm']), 0)
    pq_mean = next((r['average'] for r in res if 'PQ' in r['algorithm']), 0)
    
    fig, ax = plt.subplots(figsize=(6, 5))
    categories = ['Classical (ECDH)', 'Post-Quantum (ML-KEM)']
    values = [class_mean, pq_mean]
    
    bars = ax.bar(categories, values, color=['#dddddd', '#666666'], edgecolor='black', hatch=['', '///'], width=0.5)
    ax.set_title('Secure IPC Roundtrip Simulation (4KB Payload)')
    ax.set_ylabel('Latency (us)')
    
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.2f} us',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')
                    
    plt.savefig(os.path.join(PLOTS_DIR, 'exp5_secure_ipc.pdf'), dpi=300, format='pdf')
    plt.savefig(os.path.join(PLOTS_DIR, 'exp5_secure_ipc.png'), dpi=300)
    plt.close()
    print("Generated exp5_secure_ipc.pdf")

if __name__ == "__main__":
    print("Generating plots...")
    plot_experiment_1_and_2()
    plot_experiment_3()
    plot_experiment_4()
    plot_experiment_5()
    print("All plots generated successfully.")
