#!/bin/bash
set -euo pipefail

# =======================================================================
# Script per pulire il namespace wfns dai processi in background
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

# Verifica se il namespace esiste
if ! sudo ip netns list | grep -q "^${NS}\b"; then
    print_error "Namespace ${NS} non trovato"
    exit 1
fi

print_status "Pulizia del namespace ${NS}..."

# Lista di pattern molto specifici per i processi da terminare SOLO nel contesto esperimenti
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

# Termina solo processi specifici e sicuri
for pattern in "${SAFE_PATTERNS[@]}"; do
    if sudo ip netns exec "${NS}" pgrep -f "${pattern}" >/dev/null 2>&1; then
        print_status "Terminazione processi: ${pattern}..."
        sudo ip netns exec "${NS}" pkill -f "${pattern}" || true
        sleep 0.5
    fi
done

# NON uccidere tutti i processi utente - troppo pericoloso!
# Invece, mostra solo quali processi sono ancora attivi per il debug
print_status "Processi ancora attivi nel namespace:"
sudo ip netns exec "${NS}" ps aux --no-headers 2>/dev/null | grep -v "^root.*\[" | head -10 || true

# Verifica connessioni attive
ACTIVE_CONNECTIONS=$(sudo ip netns exec "${NS}" ss -tupln 2>/dev/null | wc -l)
if [[ $ACTIVE_CONNECTIONS -gt 1 ]]; then
    print_warning "Connessioni ancora attive:"
    sudo ip netns exec "${NS}" ss -tupln
else
    print_success "Nessuna connessione attiva nel namespace"
fi

# Test finale: verifica solo le connessioni attive (test rapido)
print_status "Verifica finale dello stato del namespace..."

FINAL_CONNECTIONS=$(sudo ip netns exec "${NS}" ss -tupln 2>/dev/null | wc -l)
if [[ $FINAL_CONNECTIONS -gt 1 ]]; then
    print_warning "Ancora $((FINAL_CONNECTIONS-1)) connessioni attive dopo la pulizia:"
    sudo ip netns exec "${NS}" ss -tupln | head -5
else
    print_success "Namespace completamente pulito - nessuna connessione attiva"
fi

print_success "Pulizia del namespace ${NS} completata"
