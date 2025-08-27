# Web Flow Evaluation Tool (wf-eval)

This project evaluates the impact of packet dropping on web traffic performance using eBPF-based packet manipulation, automated browser measurement, and statistical analysis.

## Overview

The tool simulates network conditions by dropping UDP packets at various rates and measures how this affects web page loading performance. It uses eBPF programs for packet manipulation, Selenium WebDriver for automated browsing, and network namespaces for isolation.

## Project Structure

### Core Scripts

- **`run_full_evaluation.sh`** - Main orchestration script that runs the complete evaluation pipeline
- **`install_dependencies.sh`** - Automated dependency installation for Ubuntu 22.04
- **`setup_netns.sh`** - Network namespace setup for traffic isolation
- **`run_measurements.py`** - Core measurement script using Selenium WebDriver
- **`analyse_pcaps.py`** - Packet capture analysis for network metrics
- **`plot_results.py`** - Statistical analysis and visualization generation

### Configuration Files

- **`urls.txt`** - List of websites to test (production URLs)

### eBPF Components

- **`ebpf/packet_dropper.bpf.c`** - eBPF program for packet dropping
- **`ebpf/loader.c`** - User-space program to load and control the eBPF program
- **`ebpf/Makefile`** - Build configuration for eBPF components
- **`ebpf/loader`** - Compiled eBPF loader binary
- **`ebpf/packet_dropper.bpf.o`** - Compiled eBPF object file

## Quick Start

### 1. Install Dependencies

```bash
# Run the automated installation (Ubuntu 22.04 recommended)
./install_dependencies.sh
```

This script installs:
- Basic development tools (build-essential, git, etc.)
- Python 3.x with development packages
- Chrome/Chromium browser and ChromeDriver
- eBPF development tools (libbpf, clang, linux-headers)
- Python packages (selenium, scapy, matplotlib, pandas, tqdm)

### 2. Run Complete Evaluation

```bash
# Execute the full evaluation pipeline (45-90 minutes)
./run_full_evaluation.sh
```

This will:
- Set up network namespace
- Compile eBPF programs
- Run baseline measurements (no drops)
- Run fixed drop rate experiments (0-20%)
- Run dynamic drop rate experiments
- Analyze packet captures
- Generate plots and statistics

## Manual Execution Steps

If you prefer to run components individually:

### 1. Network Setup

```bash
# Create isolated network namespace
./setup_netns.sh
```

Creates namespace `wfns` with:
- Isolated network stack
- NAT for internet access
- Custom DNS configuration

### 2. eBPF Compilation

```bash
# Build eBPF components
cd ebpf/
make clean && make
cd ..
```

### 3. Run Measurements

```bash
# Run actual measurements
python3 run_measurements.py [options]
```

Available options:
- `--urls-file`: URL list file (default: urls.txt)
- `--out-dir`: Output directory (default: out/)
- `--ns`: Network namespace (default: wfns)
- `--mode`: Experiment mode (baseline/fixed/dynamic)
- `--target-level`: Drop percentage for fixed mode
- `--runs-per-level`: Repetitions per experiment

### 4. Analysis and Visualization

```bash
# Analyze packet captures
python3 analyse_pcaps.py

# Generate plots
python3 plot_results.py
```

## Output Structure

After running the evaluation, the `out/` directory contains:

```
out/
├── nav_metrics.csv     # Navigation timing metrics
├── summary.csv         # Aggregated network statistics
├── iat_up.csv         # Uplink inter-arrival times
├── iat_down.csv       # Downlink inter-arrival times
├── pcaps/             # Raw packet captures
│   ├── baseline_*.pcap
│   ├── fixed_*.pcap
│   └── dynamic_*.pcap
└── plots/             # Generated visualizations
    ├── bar_*.png      # Bar charts with confidence intervals
    └── cdf_*.png      # Cumulative distribution functions
```

## Key Metrics

The tool measures:

- **Page Load Time**: Complete page loading duration
- **Network Traffic**: Bytes and packets sent/received
- **Flow Duration**: Total connection time
- **Inter-arrival Times**: Packet timing patterns

## Experiment Modes

1. **Baseline**: No packet dropping (reference measurements)
2. **Fixed**: Static drop rates from 0% to 20%
3. **Dynamic**: Variable drop rates during page load

## Requirements

- **OS**: Ubuntu 22.04 LTS (recommended)
- **Privileges**: Root access for network namespaces and eBPF
- **Hardware**: x86_64 or ARM64 architecture
- **Network**: Internet connectivity for website access
- **Memory**: ~2GB available RAM
- **Storage**: ~1GB for dependencies and results

## Troubleshooting

### Common Issues

1. **ChromeDriver version mismatch**:
   ```bash
   # Check Chrome and ChromeDriver compatibility
   google-chrome --version
   chromedriver --version
   ```

2. **eBPF compilation errors**:
   ```bash
   # Check kernel headers
   sudo apt install linux-headers-$(uname -r)
   ```

3. **Network namespace issues**:
   ```bash
   # Reset network setup
   sudo ip netns del wfns
   ./setup_netns.sh
   ```

4. **Permission errors**:
   ```bash
   # Ensure proper privileges
   sudo -v
   ```

### Debug Mode

Run individual components with verbose output:

```bash
# Verbose measurement run
python3 run_measurements.py --mode baseline

# Check eBPF loader
./ebpf/loader --help
```

## Development

To modify the evaluation:

1. **Add URLs**: Edit `urls.txt`
2. **Adjust drop rates**: Modify `run_measurements.py` level ranges
3. **Custom metrics**: Extend `analyse_pcaps.py` analysis
4. **New visualizations**: Add plots in `plot_results.py`

## Citation

If you use this tool in research, please include appropriate attribution and consider the ethical implications of network measurement studies.

## License

This project is provided as-is for research and educational purposes. Review and comply with applicable terms of service for websites being measured.
