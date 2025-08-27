#!/usr/bin/env python3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

OUT = Path("out")
PLOTS = OUT / "plots"
PLOTS.mkdir(parents=True, exist_ok=True)

summary = pd.read_csv(OUT / "summary.csv")
iat_up = pd.read_csv(OUT / "iat_up.csv")
iat_down = pd.read_csv(OUT / "iat_down.csv")

def agg_bar_ci(df, metric, fname, title):
    g = df.groupby("level")[metric].agg(['mean','count','std']).reset_index()
    g['sem'] = g['std'] / np.sqrt(g['count'])
    g['ci95'] = 1.96 * g['sem']

    plt.figure()
    plt.bar(g['level'].astype(str), g['mean'], yerr=g['ci95'], capsize=4)
    plt.xlabel("Drop probability (%)")
    plt.ylabel(metric)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(PLOTS / fname, dpi=180)
    plt.close()

def plot_cdf(series, fname, title, xlabel):
    if len(series) == 0: return
    x = np.sort(series.values)
    y = np.arange(1, len(x)+1) / len(x)
    plt.figure()
    plt.plot(x, y)
    plt.xlabel(xlabel)
    plt.ylabel("CDF")
    plt.title(title)
    plt.grid(True, which='both', axis='both', alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS / fname, dpi=180)
    plt.close()

# Bars + 95% CI
for m, fn, title in [
    ("plt_ms","bar_plt_ms.png","Page Load Time vs drop"),
    ("bytes_up","bar_bytes_up.png","Bytes uplink vs drop"),
    ("bytes_down","bar_bytes_down.png","Bytes downlink vs drop"),
    ("pkt_up","bar_pkt_up.png","Packets uplink vs drop"),
    ("pkt_down","bar_pkt_down.png","Packets downlink vs drop"),
    ("duration_s","bar_duration.png","Flow duration vs drop"),
]:
    agg_bar_ci(summary, m, fn, title)

# IAT CDFs per level (separate files)
for name, df in [("up", iat_up), ("down", iat_down)]:
    for lvl, sub in df.groupby("level"):
        plot_cdf(sub["iat_s"], f"cdf_iat_{name}_lvl{lvl}.png",
                 f"IAT {name.upper()} CDF – level {lvl}%", "Inter-arrival time (s)")
