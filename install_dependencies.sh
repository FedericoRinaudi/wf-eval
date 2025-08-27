#!/bin/bash
set -euo pipefail

# =======================================================================
# Dependencies installation script for wf-eval project
# Target OS: Ubuntu 22.04 LTS
# =======================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_ubuntu_version() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "Cannot detect OS version"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        print_warning "This script is designed for Ubuntu. Detected: $ID"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    if [[ "$VERSION_ID" != "22.04" ]]; then
        print_warning "This script is designed for Ubuntu 22.04. Detected: $VERSION_ID"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    print_success "OS check passed: $PRETTY_NAME"
}

update_system() {
    print_status "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    print_success "System updated"
}

install_basic_tools() {
    print_status "Installing basic development tools..."
    sudo apt install -y \
        build-essential \
        git \
        curl \
        wget \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release
    print_success "Basic tools installed"
}

install_python_dependencies() {
    print_status "Installing Python 3 and development packages..."
    sudo apt install -y \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
        python3-setuptools \
        python3-wheel
    
    print_status "Installing Python packages for the project..."
    # Create a virtual environment to avoid conflicts
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    # Update pip in virtual environment
    pip install --upgrade pip setuptools wheel
    
    # Install Python packages needed for the project
    pip install \
        selenium \
        scapy \
        pandas \
        numpy \
        matplotlib \
        tqdm \
        pathlib
    
    deactivate
    print_success "Python environment created and packages installed"
}

install_chrome_and_chromedriver() {
    print_status "Installing Google Chrome and ChromeDriver..."
    
    # Aggiungi repository Google Chrome
    wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
    echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
    
    sudo apt update
    sudo apt install -y google-chrome-stable
    
    # Installa ChromeDriver
    CHROME_VERSION=$(google-chrome --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    CHROMEDRIVER_VERSION=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROME_VERSION%%.*}")
    
    print_status "Installing ChromeDriver version $CHROMEDRIVER_VERSION for Chrome $CHROME_VERSION"
    
    wget -O /tmp/chromedriver.zip "https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip"
    sudo unzip -o /tmp/chromedriver.zip -d /usr/local/bin/
    sudo chmod +x /usr/local/bin/chromedriver
    rm /tmp/chromedriver.zip
    
    print_success "Chrome and ChromeDriver installed"
}

install_ebpf_dependencies() {
    print_status "Installing eBPF development dependencies..."
    
    # Installa kernel headers
    sudo apt install -y \
        linux-headers-$(uname -r) \
        linux-tools-$(uname -r) \
        linux-tools-common \
        linux-tools-generic
    
    # Installa LLVM/Clang per compilare eBPF
    sudo apt install -y \
        clang \
        llvm \
        gcc-multilib \
        libc6-dev
    
    # Installa libbpf e dipendenze
    sudo apt install -y \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        pkg-config
    
    print_success "eBPF dependencies installed"
}

install_networking_tools() {
    print_status "Installing networking and monitoring tools..."
    
    sudo apt install -y \
        tcpdump \
        wireshark-common \
        tshark \
        capinfos \
        iproute2 \
        iptables \
        nftables \
        netcat \
        net-tools \
        iputils-ping \
        dnsutils
    
    # Aggiungi l'utente corrente al gruppo wireshark per tcpdump senza sudo
    sudo usermod -a -G wireshark $USER
    
    print_success "Networking tools installed"
}

install_make_and_build_tools() {
    print_status "Installing build tools..."
    
    sudo apt install -y \
        make \
        cmake \
        autoconf \
        automake \
        libtool \
        pkg-config
    
    print_success "Build tools installed"
}

build_ebpf_loader() {
    print_status "Building eBPF loader..."
    
    if [[ -d "ebpf" ]]; then
        cd ebpf
        make clean || true
        make
        cd ..
        print_success "eBPF loader built successfully"
    else
        print_warning "ebpf directory not found. Make sure you're running this script from the project root."
    fi
}

setup_network_namespace() {
    print_status "Setting up network namespace (if setup_netns.sh exists)..."
    
    if [[ -f "setup_netns.sh" ]]; then
        chmod +x setup_netns.sh
        print_status "Network namespace setup script is ready. Run './setup_netns.sh' when needed."
    else
        print_warning "setup_netns.sh not found"
    fi
}

create_output_directories() {
    print_status "Creating output directories..."
    
    mkdir -p out/pcaps out/plots
    print_success "Output directories created"
}

verify_installation() {
    print_status "Verifying installation..."
    
    # Verifica Python
    if python3 --version >/dev/null 2>&1; then
        print_success "Python3: $(python3 --version)"
    else
        print_error "Python3 not found"
    fi
    
    # Verifica Chrome
    if google-chrome --version >/dev/null 2>&1; then
        print_success "Chrome: $(google-chrome --version)"
    else
        print_error "Google Chrome not found"
    fi
    
    # Verifica ChromeDriver
    if chromedriver --version >/dev/null 2>&1; then
        print_success "ChromeDriver: $(chromedriver --version)"
    else
        print_error "ChromeDriver not found"
    fi
    
    # Verifica Clang
    if clang --version >/dev/null 2>&1; then
        print_success "Clang: $(clang --version | head -1)"
    else
        print_error "Clang not found"
    fi
    
    # Verifica tcpdump
    if tcpdump --version >/dev/null 2>&1; then
        print_success "tcpdump available"
    else
        print_error "tcpdump not found"
    fi
    
    # Verifica eBPF loader
    if [[ -f "ebpf/loader" ]]; then
        print_success "eBPF loader built"
    else
        print_warning "eBPF loader not found (normal if build failed)"
    fi
}

show_usage_instructions() {
    echo
    print_success "Installation completed!"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Restart your terminal or run: source ~/.bashrc"
    echo "2. Activate the Python virtual environment: source venv/bin/activate"
    echo "3. Setup network namespace: sudo ./setup_netns.sh"
    echo "4. Run measurements: python3 run_measurements.py --mode off"
    echo
    echo -e "${BLUE}Project files overview:${NC}"
    echo "- run_measurements.py: Main measurement script"
    echo "- analyse_pcaps.py: Analyze captured packets"
    echo "- plot_results.py: Generate plots from results"
    echo "- test_cache_disabled.py: Test cache disabled functionality"
    echo "- setup_netns.sh: Setup network namespace"
    echo "- ebpf/: eBPF packet dropper implementation"
    echo
    echo -e "${YELLOW}Note:${NC} You may need to log out and log back in for group membership changes to take effect."
}

main() {
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN} wf-eval Dependencies Installer${NC}"
    echo -e "${GREEN} Ubuntu 22.04 LTS${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo
    
    check_ubuntu_version
    
    if [[ $EUID -eq 0 ]]; then
        print_error "Do not run this script as root. It will use sudo when needed."
        exit 1
    fi
    
    update_system
    install_basic_tools
    install_python_dependencies
    install_chrome_and_chromedriver
    install_ebpf_dependencies
    install_networking_tools
    install_make_and_build_tools
    build_ebpf_loader
    setup_network_namespace
    create_output_directories
    verify_installation
    show_usage_instructions
}

# Run only if script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
