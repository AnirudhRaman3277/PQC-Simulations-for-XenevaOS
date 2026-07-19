#!/bin/bash

# Ensure we are in the root directory
if [ ! -d "analysis" ] || [ ! -d "results" ]; then
    echo "Please run this script from the root project directory (PQC Simulations)."
    exit 1
fi

echo "============================================================"
echo " Starting Python Analysis Pipeline (Stage 2) "
echo "============================================================"

# Using the requested 'general' conda environment
CONDA_ENV="general"

# Path to python in the general env
PYTHON_BIN="$HOME/miniconda3/envs/$CONDA_ENV/bin/python"

if [ ! -f "$PYTHON_BIN" ]; then
    # Fallback to checking normal paths or default miniconda
    if [ -f "$HOME/miniconda/envs/$CONDA_ENV/bin/python" ]; then
        PYTHON_BIN="$HOME/miniconda/envs/$CONDA_ENV/bin/python"
    else
        echo "Error: Cannot find Python binary for conda env '$CONDA_ENV'"
        exit 1
    fi
fi

echo "Using Python: $PYTHON_BIN"

# Require pandas and matplotlib (fail fast)
$PYTHON_BIN -c "import pandas, matplotlib" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[ERROR] The 'general' conda environment is missing required packages."
    echo "Please ensure 'pandas' and 'matplotlib' are installed."
    exit 1
fi

echo ""
echo "------------------------------------------------------------"
echo " 1. Generating Plots..."
echo "------------------------------------------------------------"
$PYTHON_BIN analysis/generate_plots.py

echo ""
echo "------------------------------------------------------------"
echo " 2. Generating LaTeX Tables..."
echo "------------------------------------------------------------"
$PYTHON_BIN analysis/generate_tables.py

echo ""
echo "------------------------------------------------------------"
echo " 3. Generating Markdown Report..."
echo "------------------------------------------------------------"
# Needs tabulate for markdown output in pandas
$PYTHON_BIN -c "import tabulate" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[WARNING] 'tabulate' package not found in 'general' env. Trying pip install..."
    $PYTHON_BIN -m pip install tabulate
fi
$PYTHON_BIN analysis/generate_report.py

echo ""
echo "============================================================"
echo " Pipeline Complete! "
echo " Check the 'results/' directory for plots, tables, and the final report."
echo "============================================================"
