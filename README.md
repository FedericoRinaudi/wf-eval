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
- Run fixed drop rate experiments (1-20%)
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
- `--urls`: URL list file (default: urls.txt)
- `--ns`: Network namespace (default: wfns)
- `--mode`: Experiment mode (off/fixed/dynamic)
- `--levels`: Drop percentages for fixed mode (default: 0,1,2,5,10)
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

### Research Objectives

This framework investigates **packet dropping as a defense mechanism against website fingerprinting attacks**. We evaluate two critical aspects: (1) **privacy protection** - how effectively controlled packet dropping obfuscates QUIC traffic patterns, and (2) **performance impact** - what costs this defense imposes on user experience. The methodology follows rigorous measurement research principles to ensure reproducible and statistically valid results.

### Experimental Approach Overview

Our approach creates a controlled environment where packet dropping can be precisely applied to QUIC traffic while measuring both traffic pattern obfuscation and web performance impacts. The key insight is that by isolating the network environment and controlling packet drops at the kernel level, we can quantify the privacy-performance trade-offs of traffic obfuscation defenses.

**Experimental Flow**:
```
1. Environment Setup → 2. Baseline Measurement → 3. Defense Evaluation → 4. Analysis
       │                        │                       │                   │
       ▼                        ▼                       ▼                   ▼
   Network                 No packet              Fixed & Dynamic        Statistical
   Isolation               dropping               Drop Rates             Analysis
```

### System Architecture

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

The evaluation system creates a controlled environment with three key components:

The evaluation system creates a controlled environment with three key components:

#### 1. Network Isolation Layer

**Purpose**: Eliminate external interference and ensure measurement reproducibility.

**Implementation**: Linux network namespaces create a completely isolated network environment:
- Dedicated virtual network interface (`veth0`/`veth1`) with controlled routing
- NAT-based internet access while maintaining traffic isolation
- Custom DNS configuration (1.1.1.1, 8.8.8.8) for consistent resolution
- Bandwidth allocation: 90% for experimental traffic, 10% for host operations

**Why Critical**: Web performance measurements are severely affected by background traffic, system processes, and variable network conditions. Isolation eliminates these confounding factors.

#### 2. Traffic Obfuscation Defense (eBPF-Based Packet Dropping)

**Purpose**: Implement privacy-preserving defense against website fingerprinting by strategically modifying QUIC traffic patterns.

**Technical Implementation**: eBPF (Extended Berkeley Packet Filter) programs run directly in the kernel for precise traffic manipulation:
- **Wire-Speed Processing**: Packet drop decisions at line rate without buffering delays
- **Surgical Precision**: Only UDP packets on port 443 (QUIC) are affected
- **Minimal Overhead**: Kernel-space execution eliminates context switching costs

**Defense Strategies**:
1. **Fixed Drop Rate Mode**: Constant packet dropping percentages (1%, 2%, 5%, 10%, 20%)
   - Evaluates uniform obfuscation effectiveness across all websites
2. **Dynamic Drop Rate Mode**: Adaptive packet dropping based on traffic volume
   - Explores traffic-aware defenses that balance privacy and performance

#### 3. Measurement and Analysis Framework

**Browser Control**: Selenium WebDriver with Chrome configured for consistent, reproducible measurements:
- Clean state for each test (incognito mode, disabled cache)
- QUIC protocol enforcement and background process elimination
- Navigation Timing API for precise performance data collection

**Data Collection**: Simultaneous capture of performance metrics and traffic patterns:
- **Performance**: Page Load Time (PLT), connection duration
- **Traffic Obfuscation**: Packet counts, byte volumes, inter-arrival timing patterns

### Experimental Protocol

#### Measurement Design

**Single Page Load Flow**:
```
Load Page → Apply Defense → Capture Traffic → Measure Performance
    │            │              │                 │
    ▼            ▼              ▼                 ▼
Navigation   eBPF Packet    PCAP Analysis    Page Load Time
Timing       Dropping       (Pattern         & Connection
API          (UDP/443)      Changes)         Duration
```

**Experimental Matrix**:
- **Test Websites**: Multiple URLs from `urls.txt`
- **Defense Levels**: Baseline (off) + Fixed rates (1%, 2%, 5%, 10%, 20%) + Dynamic
- **Repetitions**: 10 runs per condition for statistical validity
- **Total Measurements**: URLs × 7 defense levels × 10 repetitions

#### Quality Assurance Controls

**Randomization**: URL testing order randomized to prevent temporal bias and learning effects

**Browser Consistency**: Standardized Chrome configuration eliminates browser-related variability:
```bash
--enable-quic                    # Ensure QUIC protocol usage
--disable-extensions            # Remove extension overhead
--incognito                     # Clean state per measurement
--disable-background-networking # Prevent interference
--disk-cache-size=1            # Force fresh network requests
```

### Data Collection and Metrics

#### Performance Evaluation Metrics

**Primary Metric**: **Page Load Time (PLT)** - calculated as `loadEventEnd - startTime`
- Represents user-visible impact of the defense mechanism
- Standardized metric enabling comparison across different websites
- Captures cumulative effect of all network interactions during page loading

**Supporting Metrics**:
- **Connection Duration**: How long QUIC connections remain active under packet loss
- **Wall-clock Timing**: Independent validation of browser-reported metrics

#### Traffic Obfuscation Analysis Metrics

**Traffic Pattern Changes** (evaluating defense effectiveness):
- **Traffic Volume**: Total bytes and packet counts in both directions
- **Packet Timing**: Inter-arrival times showing temporal pattern modifications
- **Flow Characteristics**: Connection duration changes affecting pattern recognition

**Data Capture Strategy**: Simultaneous packet capture using tcpdump with QUIC-specific filtering (`udp and port 443`) to analyze both performance impacts and obfuscation effectiveness.

### Statistical Analysis and Validation

#### Experimental Rigor

**Replication Strategy**: Multiple repetitions (default: 10 per condition) provide:
- Sufficient data for statistical significance testing
- Confidence interval calculation capability
- Accounting for natural web performance variability

**Statistical Controls**:
- **Randomization**: URL order randomized to prevent temporal and learning effects
- **Baseline Comparison**: Reference measurements without packet dropping
- **Quality Assurance**: Structured data validation and error checking

#### Data Processing Pipeline

```
Raw Measurements → Validation → Statistical Analysis → Visualization
       │              │             │                    │
       ▼              ▼             ▼                    ▼
   CSV Files      Filtering    Mean ± 95% CI         Bar Charts
   PCAP Files     Validation   Significance          CDFs
                  Aggregation  Testing               Time Series
```

**Output Structure**: Standardized CSV files enable reproducible analysis:
- `nav_metrics.csv`: Navigation timing data
- `summary.csv`: Network statistics and performance metrics  
- `iat_up.csv/iat_down.csv`: Inter-arrival time distributions for obfuscation analysis

#### Statistical Methods

**Confidence Intervals**: All results include 95% confidence intervals using standard error methods for:
- Statistical rigor in comparing experimental conditions
- Clear indication of measurement uncertainty
- Determination of statistically significant differences

**Visualization Approaches**:
- **Bar Charts**: Mean performance comparison with error bars across packet loss levels
- **Cumulative Distribution Functions (CDFs)**: Full distribution analysis of measurements
- **Time Series**: Inter-arrival time patterns demonstrating traffic obfuscation effectiveness

### Research Questions and Applications

This experimental framework enables investigation of critical questions in privacy-preserving web browsing:

1. **Performance Impact**: What is the user experience cost of packet dropping defenses?
2. **Obfuscation Effectiveness**: How successfully does controlled packet loss alter traffic patterns used for website fingerprinting?
3. **Defense Optimization**: What is the optimal balance between privacy protection and performance degradation?


## License

This project is provided as-is for research and educational purposes. Review and comply with applicable terms of service for websites being measured.
