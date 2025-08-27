#!/usr/bin/env python3
import os, csv, time, shlex, signal, tempfile, random, argparse, atexit, shutil, re, subprocess
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
from tqdm import tqdm

# -------------------------- Default config --------------------------
NS_DEFAULT = "wfns"
OUT_DIR    = Path("out")
PCAPS_DIR  = OUT_DIR / "pcaps"
CSV_PATH   = OUT_DIR / "nav_metrics.csv"
EBPF_DIR   = Path("ebpf")
LOADER_BIN = EBPF_DIR / "loader"

# -------------------------- Shell utilities ------------------------------
def sh(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def ns_sh(ns: str, cmd: str):
    return sh(f"ip netns exec {shlex.quote(ns)} sh -lc {shlex.quote(cmd)}")

def run_in_ns(ns: str, cmd: str, env=None):
    return subprocess.Popen(f"ip netns exec {shlex.quote(ns)} {cmd}", shell=True, env=env, preexec_fn=os.setsid)

# -------------------------- Chrome / Driver ----------------------------
def pick_chrome_binary():
    for p in ("/usr/bin/google-chrome","/usr/bin/google-chrome-stable","/usr/bin/chromium",
              "/usr/lib/chromium-browser/chromium-browser","/usr/bin/chromium-browser","/snap/bin/chromium"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            try:
                if "/snap/" in os.path.realpath(p):  # avoid snap if possible
                    continue
            except Exception:
                pass
            return p
    return "/snap/bin/chromium"

def get_chrome_major(ns: str, chrome_bin: str):
    out = ns_sh(ns, f"{shlex.quote(chrome_bin)} --version || true").stdout.strip()
    m = re.search(r"\b(\d+)\.", out)
    return int(m.group(1)) if m else None

def find_chromedriver_for_major(major: int):
    for p in ("/usr/bin/chromedriver","/usr/lib/chromium-browser/chromedriver",
              "/usr/lib/chromium/chromedriver","/usr/local/bin/chromedriver"):
        if os.path.exists(p) and os.access(p, os.X_OK):
            try:
                out = subprocess.run([p,"--version"], capture_output=True, text=True).stdout
                m = re.search(r"\b(\d+)\.", out)
                if int(m.group(1)) == major:
                    return p
            except Exception:
                pass
    return None

@contextmanager
def ns_wrapper(target_bin: str, ns: str):
    fd, path = tempfile.mkstemp(prefix="nswrap-", suffix=".sh")
    try:
        os.write(fd, f"#!/bin/sh\nexec ip netns exec {shlex.quote(ns)} {shlex.quote(target_bin)} \"$@\"\n".encode())
        os.fsync(fd); os.fchmod(fd, 0o755)
    finally:
        os.close(fd)
    try:
        yield path
    finally:
        try: os.unlink(path)
        except Exception: pass

# -------------------------- QUIC-only (optional) ----------------------
def quic_only_install(ns: str):
    script = r"""
add table inet quiconly 2>/dev/null
add chain inet quiconly out { type filter hook output priority 0; policy accept; } 2>/dev/null
add rule inet quiconly out udp dport 443 accept 2>/dev/null
add rule inet quiconly out tcp dport 443 reject 2>/dev/null
"""
    ns_sh(ns, "nft -f - <<'EOF'\n" + script + "EOF")

def quic_only_uninstall(ns: str):
    ns_sh(ns, "nft delete table inet quiconly 2>/dev/null || true")

# -------------------------- eBPF loader --------------------------------
_loader_proc = None

def set_loader(ns: str, mode: str, ifname: str, *, fixed_prob=None, dyn_max=None, dyn_min_pps=None, dyn_max_pps=None):
    """Manages start/stop of the loader based on mode."""
    global _loader_proc
    # stop current
    if _loader_proc and _loader_proc.poll() is None:
        try:
            os.killpg(os.getpgid(_loader_proc.pid), signal.SIGINT)
            _loader_proc.wait(timeout=3)
        except Exception:
            try: os.killpg(os.getpgid(_loader_proc.pid), signal.SIGTERM)
            except Exception: pass
    _loader_proc = None
    if mode == "off":
        return
    if not LOADER_BIN.exists():
        raise SystemExit("ERROR: build the loader first:  (cd ebpf && make)")
    if mode == "fixed":
        cmd = f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode fixed --prob {int(fixed_prob)}"
    elif mode == "dynamic":
        cmd = (f"{shlex.quote(str(LOADER_BIN))} {shlex.quote(ifname)} --mode dynamic "
               f"--max-prob {int(dyn_max)} --min-rate {int(dyn_min_pps)} --max-rate {int(dyn_max_pps)}")
    else:
        raise ValueError("unknown mode")
    _loader_proc = run_in_ns(ns, cmd)
    time.sleep(3)  # Give time for eBPF program to attach
    
    # Quick check that loader process started
    if _loader_proc.poll() is not None:
        raise SystemExit(f"[ERROR] Loader process failed to start (exit code: {_loader_proc.poll()})")

atexit.register(lambda: set_loader(NS_DEFAULT, "off", "lo"))  # best-effort

# -------------------------- Diagnostics --------------------------------
def autodetect_iface(ns: str):
    p = ns_sh(ns, "ip -o -4 route show default | awk '{print $5}'")
    if p.returncode == 0 and p.stdout.strip():
        return p.stdout.strip()
    p = ns_sh(ns, "ip -o link show | awk -F': ' '$2!~/lo/ {print $2; exit}'")
    return p.stdout.strip() or "eth0"

def ns_has_udp443(ns: str):
    return bool(ns_sh(ns, "ss -u -n | awk '$5 ~ /:443$/'").stdout.strip())

def ns_diag(ns: str):
    print("[diag] ip -br link:\n" + ns_sh(ns, "ip -br link").stdout, end="")
    print("[diag] ip -4 route:\n" + ns_sh(ns, "ip -4 route").stdout, end="")
    print("[diag] ss -u -n | head:\n" + ns_sh(ns, "ss -u -n | head -n 20").stdout, end="")
    print("[diag] nft quiconly:\n" + ns_sh(ns, "nft list ruleset | sed -n '/table inet quiconly/,$p'").stdout, end="")

# -------------------------- Navigation + measurement -----------------------
def measure_nav(ns: str, chrome_bin: str, url: str, headless: bool):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    major = get_chrome_major(ns, chrome_bin)
    if not major:
        raise SystemExit(f"Chrome not found/unreadable in {ns}: {chrome_bin}")
    cdrv = find_chromedriver_for_major(major)
    if not cdrv:
        raise SystemExit(f"chromedriver {major}.x not found. Install one aligned with Chrome {major}.x")

    with ns_wrapper(chrome_bin, ns) as chrome_in_ns:
        opts = Options()
        for a in ("--no-first-run","--disable-extensions","--disable-background-networking",
                  "--disable-sync","--incognito","--disk-cache-size=1",
                  "--disable-application-cache","--disable-back-forward-cache",
                  "--disable-background-timer-throttling","--disable-renderer-backgrounding",
                  "--disable-features=TranslateUI,BlinkGenPropertyTrees",
                  "--enable-quic","--enable-features=UseDnsHttpsSvcb,UseDnsHttpsSvcbAlpn",
                  "--no-sandbox","--disable-dev-shm-usage","--remote-debugging-pipe"):
            opts.add_argument(a)
        if headless:
            opts.add_argument("--headless=new"); opts.add_argument("--hide-scrollbars"); opts.add_argument("--disable-gpu")
        profile = tempfile.mkdtemp(prefix="chrome-prof-")
        opts.add_argument(f"--user-data-dir={profile}")
        opts.binary_location = chrome_in_ns
        drv = webdriver.Chrome(service=Service(executable_path=cdrv), options=opts)

        try:
            drv.set_page_load_timeout(120)  # Increased from 45 to 120 seconds for packet loss scenarios
            
            # Disable cache through DevTools Protocol
            drv.execute_cdp_cmd('Network.setCacheDisabled', {'cacheDisabled': True})
            drv.execute_cdp_cmd('Network.clearBrowserCache', {})
            
            t0 = time.time()
            drv.get(url)
            for _ in range(450):
                if drv.execute_script("return document.readyState") == "complete":
                    break
                time.sleep(0.1)
            nav = drv.execute_script("return performance.getEntriesByType('navigation')[0] || {}")
            plt_ms = (nav.get("loadEventEnd", 0) - nav.get("startTime", 0)) or 0
            time.sleep(5)
            return {"plt_ms": plt_ms, "t_wall_start": t0, "t_wall_end": time.time()}
        except KeyboardInterrupt:
            print(f"[INFO] Navigation interrupted by user for {url}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        except Exception as e:
            print(f"[ERROR] Navigation failed for {url}: {e}")
            return {"plt_ms": 0, "t_wall_start": t0, "t_wall_end": time.time()}
        finally:
            drv.quit()
            shutil.rmtree(profile, ignore_errors=True)

@contextmanager
def tcpdump_veth1(ns: str, outfile: Path, bpf: str):
    proc = run_in_ns(ns, f"tcpdump -i veth1 -w {shlex.quote(str(outfile))} -U -n {shlex.quote(bpf)}")
    time.sleep(0.6)
    try:
        yield
    finally:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except Exception: pass
        try: proc.wait(timeout=5)
        except Exception: pass

def capture_one(ns: str, url: str, tag: str, headless: bool, chrome_bin: str):
    pcap = PCAPS_DIR / f"{tag}.pcap"
    nav = {}
    with tcpdump_veth1(ns, pcap, "udp and port 443"):
        nav = measure_nav(ns, chrome_bin, url, headless)

    # empty pcap?
    try:
        ci = ns_sh(ns, f"capinfos -c {shlex.quote(str(pcap))} 2>/dev/null | awk -F': ' '/Number of packets/ {{print $2}}'").stdout.strip()
        pkt = int(ci) if ci.isdigit() else (pcap.stat().st_size > 24)
    except Exception:
        pkt = (pcap.stat().st_size > 24)

    if not pkt:
        print(f"[warn] empty pcap for {url}. The site may not use QUIC.")
    return str(pcap), nav or {"plt_ms":0,"t_wall_start":0,"t_wall_end":0}

# -------------------------- Main ---------------------------------------
def main():
    parser = argparse.ArgumentParser(description="QUIC WF eval runner (Selenium + tcpdump + eBPF loader)")
    parser.add_argument("--ns", default=NS_DEFAULT)
    parser.add_argument("--urls", default="urls.txt")
    parser.add_argument("--mode", choices=["off","fixed","dynamic"], required=True)
    parser.add_argument("--levels", default="0,1,2,5,10", help="per mode=fixed")
    parser.add_argument("--runs-per-level", type=int, default=10)
    parser.add_argument("--dynamic-max-prob", type=int, default=50)
    parser.add_argument("--dynamic-min-pps", type=int, default=1000)
    parser.add_argument("--dynamic-max-pps", type=int, default=100000)
    parser.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--quic-only", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()

    # prep I/O
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    PCAPS_DIR.mkdir(parents=True, exist_ok=True)

    # Verifica capacità di entrare nel namespace (errore chiaro invece di 'Operation not permitted')
    test_ns = subprocess.run(["ip", "netns", "exec", args.ns, "true"], capture_output=True)
    if test_ns.returncode != 0:
        raise SystemExit(f"Permesso negato per entrare nel namespace '{args.ns}'. "
                         f"Esegui: sudo -E ./run_full_evaluation.sh (oppure avvia questo script con sudo -E). "
                         f"Dettagli: {test_ns.stderr.decode().strip()}")

    # minimal preflight
    chrome = pick_chrome_binary()
    if args.quic_only:
        quic_only_install(args.ns)
        atexit.register(lambda: quic_only_uninstall(args.ns))

    ifname = autodetect_iface(args.ns)
    print(f"[preflight] ns={args.ns} if={ifname} chrome={chrome} major={get_chrome_major(args.ns, chrome)}")
    print("[preflight] ping 1.1.1.1 ->", ns_sh(args.ns, "ping -c1 -W1 1.1.1.1 >/dev/null && echo OK || echo FAIL").stdout.strip())

    urls = [u.strip() for u in open(args.urls) if u.strip() and not u.startswith("#")]
    random.seed(123)

    with open(CSV_PATH, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["mode","level","url","rep","pcap","plt_ms","t_wall_start","t_wall_end",
                                          "dyn_max_prob","dyn_min_pps","dyn_max_pps"])
        w.writeheader()

        if args.mode == "off":
            set_loader(args.ns, "off", ifname)
            for rep in range(1, args.runs_per_level+1):
                random.shuffle(urls)
                for url in tqdm(urls, desc=f"baseline {rep}/{args.runs_per_level}"):
                    tag = f"off_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                    pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                    w.writerow({"mode":"off","level":0,"url":url,"rep":rep,"pcap":pcap,
                                "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":""}); f.flush()

        elif args.mode == "fixed":
            levels = [int(x) for x in args.levels.split(",") if x.strip()]
            for lvl in levels:
                set_loader(args.ns, "fixed", ifname, fixed_prob=lvl)
                for rep in range(1, args.runs_per_level+1):
                    random.shuffle(urls)
                    for url in tqdm(urls, desc=f"fixed {lvl}% rep {rep}/{args.runs_per_level}"):
                        tag = f"lvl{lvl}_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                        pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                        w.writerow({"mode":"fixed","level":lvl,"url":url,"rep":rep,"pcap":pcap,
                                    "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                    "dyn_max_prob":"","dyn_min_pps":"","dyn_max_pps":""}); f.flush()
            set_loader(args.ns, "off", ifname)

        else:  # dynamic
            set_loader(args.ns, "dynamic", ifname,
                       dyn_max=args.dynamic_max_prob, dyn_min_pps=args.dynamic_min_pps, dyn_max_pps=args.dynamic_max_pps)
            for rep in range(1, args.runs_per_level+1):
                random.shuffle(urls)
                for url in tqdm(urls, desc=f"dynamic rep {rep}/{args.runs_per_level}"):
                    tag = f"dyn_rep{rep}_{url.replace('://','_').replace('/','_')}_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}"
                    pcap, nav = capture_one(args.ns, url, tag, args.headless, chrome)
                    w.writerow({"mode":"dynamic","level":-1,"url":url,"rep":rep,"pcap":pcap,
                                "plt_ms":nav["plt_ms"],"t_wall_start":nav["t_wall_start"],"t_wall_end":nav["t_wall_end"],
                                "dyn_max_prob":args.dynamic_max_prob,"dyn_min_pps":args.dynamic_min_pps,"dyn_max_pps":args.dynamic_max_pps}); f.flush()
            set_loader(args.ns, "off", ifname)

if __name__ == "__main__":
    main()
