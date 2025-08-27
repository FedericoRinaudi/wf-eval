#!/usr/bin/env bash
set -euo pipefail

# ========= CONFIG =========
NS="wfns"
VETH_HOST="veth0"
VETH_NS="veth1"
SUBNET="10.200.0.0/24"
HOST_IP="10.200.0.1"
NS_IP="10.200.0.2"
DNS1="1.1.1.1"
DNS2="8.8.8.8"
# ==========================

# Discover WAN interface (for NAT)
HOST_IF="$(ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}')"

echo "[*] Using WAN interface: ${HOST_IF}"

# Create/recreate namespace and veth idempotently
ip netns list | grep -q "^${NS}\b" || sudo ip netns add "${NS}"

# If old veth interfaces with same names exist, remove them
ip link show "${VETH_HOST}" &>/dev/null && sudo ip link del "${VETH_HOST}" || true

echo "[*] Creating veth pair ${VETH_HOST}<->${VETH_NS}"
sudo ip link add "${VETH_HOST}" type veth peer name "${VETH_NS}"
sudo ip link set "${VETH_NS}" netns "${NS}"

# Host side
echo "[*] Configuring host side ${VETH_HOST}"
sudo ip addr add "${HOST_IP}/24" dev "${VETH_HOST}" 2>/dev/null || true
sudo ip link set "${VETH_HOST}" up

# Namespace side
echo "[*] Configuring namespace ${NS} (${VETH_NS})"
sudo ip netns exec "${NS}" ip link set lo up
sudo ip netns exec "${NS}" ip addr flush dev "${VETH_NS}" || true
sudo ip netns exec "${NS}" ip addr add "${NS_IP}/24" dev "${VETH_NS}"
sudo ip netns exec "${NS}" ip link set "${VETH_NS}" up
sudo ip netns exec "${NS}" ip route replace default via "${HOST_IP}" dev "${VETH_NS}"

# Dedicated DNS in ns via /etc/netns/<ns>/resolv.conf
echo "[*] Writing /etc/netns/${NS}/resolv.conf"
sudo mkdir -p "/etc/netns/${NS}"
printf "nameserver %s\nnameserver %s\n" "${DNS1}" "${DNS2}" | sudo tee "/etc/netns/${NS}/resolv.conf" >/dev/null

# Enable IPv4 forwarding
echo "[*] Enabling IPv4 forwarding"
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Idempotent NAT (iptables)
echo "[*] Ensuring MASQUERADE rule on ${HOST_IF} for ${SUBNET}"
if ! sudo iptables -t nat -C POSTROUTING -s "${SUBNET}" -o "${HOST_IF}" -j MASQUERADE 2>/dev/null; then
  sudo iptables -t nat -A POSTROUTING -s "${SUBNET}" -o "${HOST_IF}" -j MASQUERADE
fi

# (Optional) Smaller MTU to avoid fragmentation behind VPN/PPPoE, comment if not needed
# sudo ip link set "${VETH_HOST}" mtu 1450
# sudo ip netns exec "${NS}" ip link set "${VETH_NS}" mtu 1450

# Quick self-test
echo "[*] Self-test inside namespace ${NS}"
set +e
sudo ip netns exec "${NS}" ping -c 1 -W 2 1.1.1.1 >/dev/null
PING_OK=$?
sudo ip netns exec "${NS}" getent hosts www.google.com >/dev/null
DNS_OK=$?
sudo ip netns exec "${NS}" bash -lc "command -v curl >/dev/null && curl -Is https://www.google.com | head -n1" >/dev/null
HTTP_OK=$?
set -e

if [[ $PING_OK -eq 0 && $DNS_OK -eq 0 && $HTTP_OK -eq 0 ]]; then
  echo "[✓] Namespace ${NS} ready: IP, DNS and HTTP working."
  
  # Test Chrome accessibility
  echo "[*] Testing Chrome accessibility in namespace ${NS}"
  if sudo ip netns exec "${NS}" google-chrome --version >/dev/null 2>&1; then
    echo "[✓] Chrome accessible in namespace ${NS}"
  else
    echo "[!] Warning: Chrome not accessible in namespace ${NS}"
    echo "    Make sure Chrome is installed and check file permissions"
  fi
else
  echo "[!] Warning: test failed (PING=${PING_OK}, DNS=${DNS_OK}, HTTP=${HTTP_OK})"
  echo "    Check: /etc/netns/${NS}/resolv.conf, NAT rules and ${HOST_IF} interface reachability."
fi

echo "[*] Done."
