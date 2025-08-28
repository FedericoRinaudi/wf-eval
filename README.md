# Web Flow Evaluation Tool (wf-eval)

This project evaluates the impact of packet dropping on web traffic performance using eBPF-based packet manipulation, automated browser measurement, and statistical analysis.

## Overview

The tool simulates network conditions by dropping UDP packets at various rates and measures how this affects web page loading performance. It uses eBPF programs for packet manipulation, Selenium WebDriver for automated browsing, and network namespaces for isolation.

## Project Structure

### Core Scripts

- **`run_full_evaluation.sh`** - Main orchestration script that runs the complete evaluation pipeline
- **`install_dependencies.sh`** - Automated dependency installation for Ubuntu 22.04
- **`setup_netns.sh`** - Network namespace setup for traffic isolation
- **`clean_netns.sh`** - Network namespace cleanup and process termination
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
- **`nav_metrics.csv`** - Navigation timing metrics
- **`summary.csv`** - Aggregated network statistics  
- **`iat_up.csv, iat_down.csv`** - Inter-arrival time distributions
- **`pcaps/`** - Raw packet captures for detailed analysis
- **`plots/`** - Generated visualizations (bar charts and CDFs)

**Key Metrics**: Page Load Time, Network Traffic (bytes/packets), Flow Duration, Inter-arrival Times

## Requirements

- **OS**: Ubuntu 22.04 LTS (recommended)
- **Privileges**: Root access for network namespaces and eBPF
- **Hardware**: x86_64 or ARM64 architecture
- **Network**: Internet connectivity for website access
- **Memory**: ~2GB available RAM
- **Storage**: ~1GB for dependencies and results

## Development

**Customization**: Edit `urls.txt` for different websites, modify drop rates in `run_measurements.py`, extend analysis in `analyse_pcaps.py`, or add visualizations in `plot_results.py`.

## Citation

If you use this tool in research, please include appropriate attribution and consider the ethical implications of network measurement studies.

## Experimental Design and Methodology

This framework implements a controlled experimental methodology to quantify packet loss impact on QUIC protocol web performance, following established network measurement research principles.

### Experimental Architecture

#### 1. Traffic Isolation and Control

**Network Namespace Isolation**: The system employs Linux network namespaces (`wfns`) to create a completely isolated network stack. This prevents interference from host system traffic and enables precise control over experimental conditions. The namespace setup includes:

- Dedicated virtual ethernet pair (`veth0`/`veth1`) connecting host and namespace
- Custom routing table with controlled default gateway
- Isolated DNS configuration (1.1.1.1, 8.8.8.8) for consistent resolution
- NAT-based internet connectivity maintaining isolation

**Traffic Control (TC) Implementation**: A hierarchical traffic shaping system using HTB (Hierarchical Token Bucket) qdisc provides bandwidth prioritization:
- Namespace traffic: 90% bandwidth allocation (rate: 90mbit, ceil: 95mbit)
- Host traffic: 10% bandwidth allocation (rate: 10mbit, ceil: 20mbit)
- This prevents background applications from affecting measurement accuracy

#### 2. QUIC Protocol Enforcement

**Selective Protocol Blocking**: The framework optionally implements nftables rules to enforce QUIC-only traffic:
```
UDP/443 → ACCEPT (QUIC traffic)
TCP/443 → REJECT (Force QUIC fallback prevention)
```

This ensures measurements specifically target QUIC protocol performance rather than mixed protocol scenarios, providing cleaner experimental conditions for packet loss impact analysis.

#### 3. eBPF-Based Packet Manipulation

**Kernel-Level Precision**: The packet dropping mechanism uses eBPF (Extended Berkeley Packet Filter) programs attached to traffic control hooks, providing:

- **Minimal Overhead**: Kernel-space execution eliminates userspace context switching delays
- **Precise Timing**: Packet decisions made at wire speed without buffering delays
- **Selective Targeting**: UDP-specific dropping to simulate QUIC congestion scenarios

**Operating Modes**:

1. **Fixed Mode**: Constant drop probability (0-20%) for controlled loss rate analysis
   - Enables direct correlation between loss rate and performance degradation
   - Provides baseline measurements for statistical comparison

2. **Dynamic Mode**: Adaptive dropping based on real-time traffic rate
   - Simulates realistic network congestion scenarios
   - Higher traffic volumes trigger proportionally higher loss rates
   - Models bandwidth competition and network saturation effects

### Measurement Methodology

#### 1. Browser Automation and Consistency

**Chrome Configuration**: Selenium WebDriver controls a hardened Chrome instance with optimized settings:

```bash
--enable-quic                    # Force QUIC protocol usage
--disable-extensions            # Eliminate browser overhead
--incognito                     # Clean state for each measurement
--disable-background-networking # Prevent interference traffic
--disk-cache-size=1            # Force network fetches
--no-sandbox                   # Namespace compatibility
```

**Performance Timing Collection**: Navigation Timing API provides microsecond-precision metrics:
- `performance.getEntriesByType('navigation')[0]`
- Page Load Time (PLT): `loadEventEnd - startTime`
- Wall-clock timing for validation

#### 2. Network Traffic Capture and Analysis

**Packet Capture Strategy**: Simultaneous tcpdump capture with BPF filter `"udp and port 443"`:
- Records all QUIC traffic during page navigation
- Enables post-measurement verification of dropping effectiveness
- Provides data for inter-arrival time analysis and flow characterization

**Metrics Extraction**:
- **Bytes Up/Down**: Total traffic volume in each direction
- **Packet Counts**: Discrete packet statistics for rate analysis
- **Flow Duration**: Complete connection lifetime measurement
- **Inter-Arrival Times**: Packet timing distributions for congestion analysis

### Statistical Design

#### 1. Experimental Controls

**Randomization**: URL ordering randomized per repetition to minimize ordering effects and temporal biases.

**Replication**: Multiple repetitions (default: 10) per experimental condition ensure statistical significance and confidence interval calculation.

**Baseline Establishment**: 'Off' mode provides reference measurements without any packet manipulation for relative performance calculation.

#### 2. Data Collection Structure

The evaluation generates structured datasets for rigorous analysis:

```csv
# Navigation Metrics (nav_metrics.csv)
mode,level,url,rep,pcap,plt_ms,t_wall_start,t_wall_end

# Network Summary (summary.csv)  
url,level,rep,pcap,plt_ms,bytes_up,bytes_down,pkt_up,pkt_down,duration_s

# Inter-Arrival Time Distributions (iat_up.csv, iat_down.csv)
url,level,rep,iat_s
```

### Experimental Validation

#### 1. Connectivity and Protocol Verification

**Pre-flight Checks**:
- Namespace connectivity validation (`ping 1.1.1.1`)
- Chrome/ChromeDriver version compatibility verification
- QUIC support confirmation via UDP/443 traffic detection

**Real-time Monitoring**:
- eBPF program attachment verification
- Packet capture validation (non-empty pcap files)
- Network interface status monitoring

#### 2. Quality Assurance

**Timeout Handling**: Extended page load timeout (120s) accommodates high packet loss scenarios while preventing indefinite hangs.

**Error Recovery**: Graceful handling of navigation failures, network timeouts, and browser crashes with continued experiment execution.

**Cleanup Procedures**: Automatic cleanup of temporary profiles, network configurations, and background processes ensures clean experimental state.

### Analytical Framework

#### 1. Performance Metrics

**Primary Metrics**:
- **Page Load Time (PLT)**: End-to-end web page loading duration
- **Traffic Volume**: Bidirectional byte and packet counts
- **Flow Characteristics**: Connection duration and packet timing patterns

**Derived Metrics**:
- **Performance Degradation**: Relative increase from baseline measurements
- **Traffic Efficiency**: Bytes per successful page load
- **Protocol Behavior**: QUIC congestion response patterns

#### 2. Visualization and Statistical Analysis

**Confidence Intervals**: 95% confidence intervals using standard error calculations for robust statistical comparison.

**Comparative Analysis**: 
- Bar charts with error bars for cross-condition comparison
- Cumulative Distribution Functions (CDFs) for distribution analysis
- Inter-arrival time analysis for protocol behavior characterization

### Research Applications

This framework enables investigation of several research questions:

1. **QUIC Resilience**: How does QUIC protocol performance degrade under various packet loss conditions?

2. **Congestion Response**: How do different websites adapt their traffic patterns to network congestion?

3. **Performance Modeling**: Can we model the relationship between packet loss and web performance for capacity planning?

4. **Protocol Comparison**: How does QUIC performance compare to TCP under identical network conditions?

### Ethical and Reproducibility Considerations

**Website Selection**: The default URL list includes major websites with known QUIC support, representing diverse content types and geographic distributions.

**Rate Limiting**: Measurement intervals and repetitions are designed to avoid excessive load on target websites.

**Reproducibility**: All experimental parameters are configurable and documented, enabling replication with different URL sets, network conditions, or measurement scales.

**Privacy**: All measurements are conducted from isolated network namespaces with no persistent data storage or user tracking.

## License

This project is provided as-is for research and educational purposes. Review and comply with applicable terms of service for websites being measured.
