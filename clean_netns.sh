#!/bin/bash
set -euo pipefail

# =======================================================================
# Script to clean wfns namespace from background processes
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

NS="wfns"

# Check if namespace exists
if ! sudo ip netns list | grep -q "^${NS}\b"; then
    print_error "Namespace ${NS} not found"
    exit 1
fi

print_status "Cleaning namespace ${NS}..."

# List of very specific patterns for processes to terminate ONLY in experiment context
SAFE_PATTERNS=(
    "chrome --enable-quic"
    "chrome --headless"
    "chrome --no-sandbox.*--remote-debugging"
    "chromedriver.*--port"
    "google-chrome --enable-quic"
    "google-chrome --headless"
    "google-chrome --no-sandbox.*--remote-debugging"
    "chromium --enable-quic"
    "chromium --headless"
    "selenium"
    "python.*run_measurements"
    "tcpdump.*veth1"
    "tcpdump -i veth1"
)

# Terminate only specific and safe processes
for pattern in "${SAFE_PATTERNS[@]}"; do
    if sudo ip netns exec "${NS}" pgrep -f "${pattern}" >/dev/null 2>&1; then
        print_status "Terminating processes: ${pattern}..."
        sudo ip netns exec "${NS}" pkill -f "${pattern}" || true
        sleep 0.5
    fi
done

# DON'T kill all user processes - too dangerous!
# Instead, only show which processes are still active for debugging
print_status "Processes still active in namespace:"
sudo ip netns exec "${NS}" ps aux --no-headers 2>/dev/null | grep -v "^root.*\[" | head -10 || true

# Check active connections
ACTIVE_CONNECTIONS=$(sudo ip netns exec "${NS}" ss -tupln 2>/dev/null | wc -l)
if [[ $ACTIVE_CONNECTIONS -gt 1 ]]; then
    print_warning "Connections still active:"
    sudo ip netns exec "${NS}" ss -tupln
else
    print_success "No active connections in namespace"
fi

# Final test: check only active connections (quick test)
print_status "Final verification of namespace state..."

FINAL_CONNECTIONS=$(sudo ip netns exec "${NS}" ss -tupln 2>/dev/null | wc -l)
if [[ $FINAL_CONNECTIONS -gt 1 ]]; then
    print_warning "Still $((FINAL_CONNECTIONS-1)) active connections after cleanup:"
    sudo ip netns exec "${NS}" ss -tupln | head -5
else
    print_success "Namespace completely clean - no active connections"
fi

print_success "Namespace ${NS} cleanup completed"
