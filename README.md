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

This framework quantifies how packet loss affects QUIC protocol performance through controlled network experiments. The methodology follows rigorous measurement research principles to ensure reproducible and statistically valid results.

### Core Experimental Setup

The evaluation system creates a controlled environment where packet loss can be precisely applied to web traffic while measuring its impact on page loading performance. The key insight is that by isolating the network environment and controlling packet drops at the kernel level, we can establish clear cause-and-effect relationships between network conditions and web performance.

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

#### Packet Loss Simulation

**eBPF-Based Approach**: Traditional packet loss simulation tools (like `tc netem`) operate in userspace and can introduce timing artifacts. This framework uses eBPF (Extended Berkeley Packet Filter) programs that run directly in the kernel for precise packet manipulation:

- **Wire-Speed Processing**: Packet drop decisions are made at line rate without buffering delays
- **Surgical Precision**: Only UDP packets on port 443 (QUIC traffic) are affected
- **Minimal System Impact**: Kernel-space execution eliminates context switching overhead

**Two Experimental Modes**:

1. **Fixed Drop Rate Mode**: Applies constant packet loss percentages (0%, 5%, 10%, 15%, 20%)
   - Purpose: Establish direct correlation between loss rate and performance impact
   - Use case: Understanding QUIC's resilience to different congestion levels

2. **Dynamic Drop Rate Mode**: Packet loss adapts based on traffic volume
   - Purpose: Simulate realistic network congestion where higher traffic leads to more drops
   - Use case: Understanding how QUIC performs under varying network load

### Measurement Process

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

**Packet Capture Strategy**: Simultaneous with browser measurements, the system captures all network traffic using tcpdump with a specific filter for QUIC traffic (`udp and port 443`). This serves multiple purposes:

1. **Verification**: Confirms that packet dropping is working as intended
2. **Traffic Characterization**: Analyzes how different websites use QUIC protocol
3. **Inter-arrival Time Analysis**: Studies packet timing patterns under different loss conditions

**Key Metrics Extracted**:
- **Traffic Volume**: Total bytes and packet counts in both directions (upload/download)
- **Flow Duration**: How long the QUIC connection remains active
- **Packet Timing**: Inter-arrival times reveal protocol behavior under stress

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

**Quality Controls**:
- **Timeout Handling**: 120-second page load timeout accommodates high packet loss scenarios
- **Error Recovery**: Graceful handling of navigation failures and browser crashes
- **Data Validation**: Non-empty packet captures confirm successful measurements
- **Connectivity Verification**: Pre-flight checks ensure experimental setup is working

### Analysis and Interpretation

#### Performance Metrics

**Primary Measurement**: Page Load Time (PLT) serves as the main performance indicator because:
- It represents the user-visible impact of network conditions
- It's a standardized metric across different websites
- It captures the cumulative effect of all network interactions during page loading

**Supporting Metrics**:
- **Traffic Volume**: How much data is transferred (indicates protocol efficiency)
- **Connection Duration**: How long QUIC maintains connections (reveals protocol behavior)
- **Packet Timing Patterns**: Inter-arrival times show how packet loss affects protocol dynamics

#### Statistical Analysis Approach

**Confidence Intervals**: All results include 95% confidence intervals calculated using standard error methods. This provides:
- Statistical rigor for comparing different experimental conditions
- Clear indication of measurement uncertainty
- Basis for determining statistically significant differences

**Comparative Visualization**:
- **Bar Charts**: Show mean performance with error bars for direct comparison across packet loss levels
- **Cumulative Distribution Functions (CDFs)**: Reveal the full distribution of performance measurements
- **Time Series Analysis**: Inter-arrival time plots show how packet loss affects protocol timing

### Research Applications and Insights

This experimental framework enables investigation of several important questions about modern web performance:

#### Core Research Questions

1. **QUIC Resilience**: How much packet loss can QUIC tolerate before performance significantly degrades?
   - Baseline measurements establish normal performance
   - Fixed drop rate experiments reveal degradation thresholds
   - Results inform network capacity planning

2. **Protocol Adaptation**: How does QUIC modify its behavior under different network conditions?
   - Packet timing analysis reveals congestion control responses
   - Traffic volume changes show protocol adaptation strategies
   - Connection duration patterns indicate retry and timeout behaviors

3. **Website Variability**: Do different websites respond differently to identical network conditions?
   - Multi-site measurements reveal implementation differences
   - Content type effects (video, images, text) become apparent
   - CDN and server infrastructure impacts are measurable

#### Practical Applications

**Network Planning**: Results help network operators understand:
- What packet loss levels are acceptable for good web performance
- How much bandwidth is needed to maintain quality of experience
- Where to invest in infrastructure improvements

**Protocol Development**: Insights inform QUIC protocol improvements:
- Identifying scenarios where performance degrades unexpectedly
- Understanding how different congestion control algorithms perform
- Revealing opportunities for protocol optimization

### Experimental Validation and Limitations

#### Built-in Validation Mechanisms

**Connectivity Verification**: Before each experiment, the system verifies:
- Network namespace has internet connectivity (`ping 1.1.1.1`)
- Chrome and ChromeDriver versions are compatible
- QUIC protocol support is available and functioning

**Real-time Monitoring**: During measurements, the system checks:
- eBPF programs are properly attached and functioning
- Packet captures contain expected QUIC traffic
- Browser successfully loads pages within timeout limits

#### Limitations and Considerations

**Website Dependencies**: Results depend on:
- Website server implementations of QUIC
- CDN configurations and geographic distribution
- Dynamic content that may vary between measurements

**Environment Factors**: Measurements are affected by:
- Internet connection quality and latency
- System resource availability (CPU, memory)
- Time-of-day effects on website performance

**Scope Boundaries**: This framework specifically measures:
- QUIC protocol performance (not TCP-based alternatives)
- Page load completion (not interactive user experience)
- Packet loss effects (not bandwidth limitations or latency)

### Reproducibility and Ethical Considerations

#### Ensuring Reproducible Results

**Documented Configuration**: All experimental parameters are configurable and documented:
- URL lists can be customized for different website sets
- Packet loss levels and measurement repetitions are adjustable
- Analysis scripts can be modified for different research questions

**Standardized Environment**: The framework provides:
- Automated dependency installation for consistent setup
- Isolated network environment that eliminates host system interference
- Deterministic eBPF-based packet manipulation

#### Ethical Research Practices

**Responsible Measurement**: The framework implements:
- Rate limiting to avoid excessive load on target websites
- Measurement intervals that respect website terms of service
- Privacy protection through isolated network namespaces

**Transparency**: All measurement methodologies are documented to enable:
- Peer review of experimental design
- Replication by independent researchers
- Comparison with alternative measurement approaches

## License

This project is provided as-is for research and educational purposes. Review and comply with applicable terms of service for websites being measured.
