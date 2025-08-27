#!/usr/bin/env python3
import csv
from pathlib import Path
from scapy.all import PcapReader, UDP

NAV_CSV = Path("out/nav_metrics.csv")
SUMMARY_CSV = Path("out/summary.csv")
IAT_UP = Path("out/iat_up.csv")
IAT_DOWN = Path("out/iat_down.csv")

def load_runs():
    with open(NAV_CSV) as f:
        return list(csv.DictReader(f))

def analyse_pcap(pcap_path: str):
    first_ts = last_ts = None
    bytes_up = bytes_down = 0
    pkt_up = pkt_down = 0
    last_ts_up = last_ts_down = None
    iats_up, iats_down = [], []

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            if not pkt.haslayer(UDP):
                continue
            udp = pkt[UDP]
            ts = float(pkt.time)
            sport, dport = int(udp.sport), int(udp.dport)

            if dport == 443:  # client -> server
                pkt_up += 1; bytes_up += len(bytes(pkt))
                if last_ts_up is not None: iats_up.append(ts - last_ts_up)
                last_ts_up = ts
            elif sport == 443:  # server -> client
                pkt_down += 1; bytes_down += len(bytes(pkt))
                if last_ts_down is not None: iats_down.append(ts - last_ts_down)
                last_ts_down = ts
            else:
                continue

            if first_ts is None: first_ts = ts
            last_ts = ts

    duration = (last_ts - first_ts) if (first_ts and last_ts) else 0.0
    return {
        "bytes_up": bytes_up, "bytes_down": bytes_down,
        "pkt_up": pkt_up, "pkt_down": pkt_down,
        "duration_s": duration, "iats_up": iats_up, "iats_down": iats_down
    }

def main():
    runs = load_runs()
    SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(SUMMARY_CSV, "w", newline="") as fs, \
         open(IAT_UP, "w", newline="") as fu, \
         open(IAT_DOWN, "w", newline="") as fd:
        ws = csv.DictWriter(fs, fieldnames=[
            "url","level","rep","pcap","plt_ms","bytes_up","bytes_down","pkt_up","pkt_down","duration_s"
        ])
        ws.writeheader()
        wi_u = csv.DictWriter(fu, fieldnames=["url","level","rep","iat_s"]); wi_u.writeheader()
        wi_d = csv.DictWriter(fd, fieldnames=["url","level","rep","iat_s"]); wi_d.writeheader()

        for row in runs:
            res = analyse_pcap(row["pcap"])
            ws.writerow({
                "url": row["url"], "level": int(row["level"]), "rep": int(row["rep"]),
                "pcap": row["pcap"], "plt_ms": float(row["plt_ms"]),
                "bytes_up": res["bytes_up"], "bytes_down": res["bytes_down"],
                "pkt_up": res["pkt_up"], "pkt_down": res["pkt_down"],
                "duration_s": res["duration_s"]
            })
            for x in res["iats_up"]:
                wi_u.writerow({"url": row["url"], "level": int(row["level"]), "rep": int(row["rep"]), "iat_s": x})
            for x in res["iats_down"]:
                wi_d.writerow({"url": row["url"], "level": int(row["level"]), "rep": int(row["rep"]), "iat_s": x})

if __name__ == "__main__":
    main()
