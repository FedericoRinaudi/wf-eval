# Web Flow Evaluation Tool (wf-eval)

This project evaluates packet dropping defenses against website fingerprinting attacks, measuring both their effectiveness at traffic pattern obfuscation and their impact on web performance using eBPF-based packet manipulation, automated browser measurement, and statistical analysis.

## Overview

The tool implements controlled packet dropping techniques to obfuscate QUIC traffic patterns as a defense against website fingerprinting attacks, while measuring the performance impact of such privacy-preserving modifications. It evaluates two aspects: (1) how effectively packet dropping alters traffic patterns for privacy protection, and (2) what performance costs this defense imposes on users. The framework uses eBPF programs for precise packet manipulation, Selenium WebDriver for automated browsing, and network namespaces for traffic isolation.

## Project Structure

### Core Scripts

- **`run_full_evaluation.sh`** - Main orchestration script that runs the complete evaluation pipeline
- **`install_dependencies.sh`** - Automated dependency installation for Ubuntu 22.04
- **`setup_netns.sh`** - Network namespace setup for traffic isolation
- **`clean_netns.sh`** - Network namespace cleanup and process termination
- **`run_measurements.py`** - Core measurement script using Selenium WebDriver for performance evaluation
- **`analyse_pcaps.py`** - Packet capture analysis for network metrics and traffic pattern obfuscation analysis
- **`plot_results.py`** - Statistical analysis and visualization generation for both performance and obfuscation metrics

### Configuration Files

- **`urls.txt`** - List of websites to test (production URLs)

### eBPF Components

- **`ebpf/packet_dropper.bpf.c`** - eBPF program for packet dropping
- **`ebpf/loader.c`** - User-space program to load and control the eBPF program
- **`ebpf/Makefile`** - Build configuration for eBPF components
- **`ebpf/loader`** - Compiled eBPF loader binary
- **`ebpf/packet_dropper.bpf.o`** - Compiled eBPF object file

## Quick Start

### 1. Set Execute Permissions

First, make the scripts executable:

```bash
# Make all shell scripts executable
chmod +x install_dependencies.sh
chmod +x run_full_evaluation.sh
chmod +x setup_netns.sh
chmod +x clean_netns.sh
```

### 2. Install Dependencies

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

### 3. Run Complete Evaluation

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

### 5. Cleanup (Optional)

```bash
# Clean namespace from background processes if needed
./clean_netns.sh
```

## Output Structure

The `out/` directory contains:
- **`nav_metrics.csv`** - Navigation timing metrics (performance evaluation)
- **`summary.csv`** - Aggregated network statistics (performance + obfuscation analysis)
- **`iat_up.csv, iat_down.csv`** - Inter-arrival time distributions (traffic pattern obfuscation analysis)
- **`pcaps/`** - Raw packet captures for detailed analysis
- **`plots/`** - Generated visualizations (bar charts and CDFs)

**Performance Metrics**: Page Load Time, Flow Duration  
**Traffic Obfuscation Metrics**: Network Traffic (bytes/packets), Inter-arrival Times


## Experimental Design and Methodology

This framework investigates how controlled packet dropping can alter QUIC traffic patterns as a defense mechanism against website fingerprinting attacks, while measuring the performance impact of such traffic obfuscation techniques. The methodology follows rigorous measurement research principles to ensure reproducible and statistically valid results.

### System Architecture Overview

```
┌─────────────────────────────────────────────┐
│            NETWORK NAMESPACE                │
│                                             │
│  ┌─────────────┐  ┌─────────────┐           │
│  │   Browser   │  │ eBPF Packet │           │
│  │   + Selenium│  │ Dropper     │           │
│  │             │  │ (UDP/443)   │           │
│  └─────────────┘  └─────────────┘           │
│         │                 │                 │
│         ▼                 ▼                 │
│  ┌─────────────────────────────────────────┐│
│  │      Network Interface (veth)           ││
│  └─────────────────────────────────────────┘│
└─────────────────┬───────────────────────────┘
                  │
           ┌──────▼──────┐
           │  INTERNET   │
           │ (Test Sites)│
           └─────────────┘
```

### Experimental Flow

```
Setup → Pre-flight Checks → Baseline → Fixed Drop Rates → Dynamic Drop → Analysis
  │           │                │           │                │            │
  ▼           ▼                ▼           ▼                ▼            ▼
Network     Browser          No drops    0-20% rates     Traffic-based  Statistics
Namespace   Validation                                   congestion     & Plots
```

### Core Experimental Setup

The evaluation system creates a controlled environment where packet dropping can be precisely applied to QUIC traffic to study traffic pattern obfuscation techniques while measuring their impact on web performance. The key insight is that by isolating the network environment and controlling packet drops at the kernel level, we can evaluate the effectiveness of traffic obfuscation defenses against website fingerprinting while quantifying their performance costs.

#### Network Isolation Architecture

**Why Isolation Matters**: Web performance measurements can be severely affected by background traffic, system processes, and variable network conditions. To eliminate these confounding factors, the framework creates a completely isolated network environment.

**Implementation**: The system uses Linux network namespaces to create a separate network stack:
- A dedicated virtual network interface (`veth0`/`veth1`) connects the isolated environment to the host
- Custom routing ensures all test traffic flows through controlled paths
- NAT provides internet access while maintaining isolation
- DNS is configured to use reliable public servers (1.1.1.1, 8.8.8.8)

**Traffic Prioritization**: The framework implements bandwidth allocation to prevent interference:
- 90% bandwidth allocated to experimental traffic
- 10% reserved for host system operations
- This ensures consistent network conditions during measurements

#### Traffic Obfuscation Defense

**eBPF-Based Approach**: This framework implements a privacy-preserving defense against website fingerprinting attacks by strategically dropping QUIC packets to obfuscate traffic patterns. Unlike traditional packet loss simulation tools, this uses eBPF (Extended Berkeley Packet Filter) programs that run directly in the kernel for precise traffic manipulation:

- **Wire-Speed Processing**: Packet drop decisions are made at line rate without buffering delays
- **Surgical Precision**: Only UDP packets on port 443 (QUIC traffic) are affected to alter fingerprinting features
- **Minimal System Impact**: Kernel-space execution eliminates context switching overhead

**Two Defense Strategies**:

1. **Fixed Drop Rate Mode**: Applies constant packet dropping percentages (0%, 5%, 10%, 15%, 20%)
   - Purpose: Establish consistent traffic pattern obfuscation across all websites
   - Use case: Evaluating the privacy-performance trade-off of uniform packet dropping defenses

2. **Dynamic Drop Rate Mode**: Packet dropping adapts based on traffic volume
   - Purpose: Implement adaptive obfuscation that responds to website traffic characteristics
   - Use case: Understanding how traffic-aware defenses can balance privacy protection with performance

### Measurement Process

#### Single Page Load Measurement Flow

```
Browser loads page → eBPF drops packets → Capture traffic → Measure performance
      │                      │                   │                │
      ▼                      ▼                   ▼                ▼
Navigation Timing      UDP/443 filtering    PCAP analysis    Page Load Time
```

#### Experimental Design

- **Multiple websites** tested from `urls.txt`
- **Packet loss levels**: 0%, 5%, 10%, 15%, 20%, Dynamic
- **Repetitions**: 10 runs per condition for statistical validity
- **Total measurements**: URLs × 6 levels × 10 repetitions

#### Browser Configuration and Control

**Consistent Testing Environment**: Achieving reproducible web performance measurements requires eliminating browser-related variability. The framework uses Selenium WebDriver to control Chrome with carefully selected options:

```bash
--enable-quic                    # Ensure QUIC protocol is used when available
--disable-extensions            # Remove browser extension overhead
--incognito                     # Start with clean state (no cache, cookies, history)
--disable-background-networking # Prevent interference from browser background processes
--disk-cache-size=1            # Force fresh network requests
--no-sandbox                   # Required for operation in network namespace
```

**Why These Settings Matter**: 
- Incognito mode ensures each measurement starts with a clean browser state
- Disabled cache forces actual network traffic for every test
- QUIC enablement ensures we're measuring the target protocol
- Background process disabling prevents interference from browser telemetry

**Performance Data Collection**: The framework captures timing data through the browser's Navigation Timing API:
- `performance.getEntriesByType('navigation')[0]` provides detailed timing breakdown
- **Page Load Time (PLT)**: Calculated as `loadEventEnd - startTime`
- Wall-clock timing provides independent validation of browser-reported metrics

#### Network Traffic Analysis

**Packet Capture Strategy**: Simultaneous with browser measurements, the system captures all network traffic using tcpdump with a specific filter for QUIC traffic (`udp and port 443`). This captures both performance impacts and traffic pattern changes for obfuscation effectiveness analysis.

**Metrics for Performance Evaluation**:
- **Flow Duration**: How long the QUIC connection remains active under packet loss conditions

**Metrics for Traffic Obfuscation Analysis**:
- **Traffic Volume**: Total bytes and packet counts in both directions (reveals how packet dropping alters traffic fingerprinting features)
- **Packet Timing**: Inter-arrival times show how the defense modifies temporal traffic patterns that could be used for website identification

### Statistical Methodology

#### Experimental Controls

**Randomization**: URL order is randomized for each experimental run to prevent:
- Temporal bias (network conditions changing over time)
- Learning effects (browser or network caching across measurements)
- Systematic ordering effects that could skew results

**Replication Strategy**: Each experimental condition is repeated multiple times (default: 10 repetitions):
- Provides sufficient data for statistical significance testing
- Enables calculation of confidence intervals
- Accounts for natural variability in web performance

**Baseline Establishment**: Every experiment includes measurements with packet dropping disabled ('Off' mode):
- Provides reference performance under normal conditions
- Enables calculation of relative performance degradation
- Accounts for natural website performance variations

#### Data Structure and Quality Assurance

**Structured Output**: The system generates standardized CSV files for analysis:

```csv
# Navigation timing data (nav_metrics.csv)
mode,level,url,rep,pcap,plt_ms,t_wall_start,t_wall_end

# Network statistics (summary.csv)
url,level,rep,pcap,plt_ms,bytes_up,bytes_down,pkt_up,pkt_down,duration_s

# Packet timing analysis (iat_up.csv, iat_down.csv)
url,level,rep,iat_s
```

### Analysis and Interpretation

#### Data Analysis Pipeline

```
Raw Data → Processing → Statistical Analysis → Visualization
   │           │              │                    │
   ▼           ▼              ▼                    ▼
CSV files   Filtering    Mean ± 95% CI        Bar Charts
PCAP files  Validation   Significance         CDFs
            Aggregation  Correlation          Time Series
```

#### Performance Metrics

**Primary Performance Measurement**: Page Load Time (PLT) serves as the main performance indicator because:
- It represents the user-visible impact of network conditions
- It's a standardized metric across different websites
- It captures the cumulative effect of all network interactions during page loading

**Traffic Obfuscation Analysis Metrics**:
- **Traffic Volume**: Packet counts and byte patterns (evaluates how effectively packet dropping alters fingerprinting features)
- **Packet Timing Patterns**: Inter-arrival times analyze how packet loss modifies temporal traffic characteristics
- **Connection Duration**: Flow timing changes that affect traffic pattern recognition

**Supporting Performance Metrics**:
- **Connection Duration**: How long QUIC maintains connections (reveals protocol efficiency under packet loss)

#### Statistical Analysis Approach

**Confidence Intervals**: All results include 95% confidence intervals calculated using standard error methods. This provides:
- Statistical rigor for comparing different experimental conditions
- Clear indication of measurement uncertainty
- Basis for determining statistically significant differences

**Comparative Visualization**:
- **Bar Charts**: Show mean performance with error bars for direct comparison across packet loss levels
- **Cumulative Distribution Functions (CDFs)**: Reveal the full distribution of performance measurements  
- **Time Series Analysis**: Inter-arrival time plots demonstrate how the packet dropping defense alters traffic timing patterns for obfuscation

### Research Applications and Insights

This experimental framework enables investigation of several important questions about traffic obfuscation and privacy-preserving web browsing:

**Performance Impact Analysis**: How does packet dropping as a defense mechanism affect user experience?
**Traffic Obfuscation Effectiveness**: How successfully does controlled packet loss alter traffic patterns that could be used for website fingerprinting?


## License

This project is provided as-is for research and educational purposes. Review and comply with applicable terms of service for websites being measured.
