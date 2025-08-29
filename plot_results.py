#!/usr/bin/env python3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

OUT = Path("out")
PLOTS = OUT / "plot"  # Use out/plot directory
PLOTS.mkdir(parents=True, exist_ok=True)

summary = pd.read_csv(OUT / "summary.csv")
iat_up = pd.read_csv(OUT / "iat_up.csv")
iat_down = pd.read_csv(OUT / "iat_down.csv")

# Debug: Print data summary
print(f"Summary data shape: {summary.shape}")
print(f"Levels found: {sorted(summary['level'].unique())}")
print(f"Level counts: {summary['level'].value_counts().sort_index()}")
print(f"Metrics available: {list(summary.columns)}")
print()

def format_value_with_unit(value, unit):
    """Format values with appropriate unit conversion for readability"""
    if unit == "bytes":
        if value >= 1024*1024:
            return f"{value/(1024*1024):.1f}", "MB"
        elif value >= 1024:
            return f"{value/1024:.1f}", "KB" 
        else:
            return f"{value:.0f}", "bytes"
    elif unit == "ms" and value >= 1000:
        return f"{value/1000:.2f}", "seconds"
    else:
        return f"{value:.1f}", unit

def agg_bar_ci(df, metric, fname, title, ylabel=None, unit=""):
    """Create bar chart with confidence intervals and professional styling"""
    g = df.groupby("level")[metric].agg(['mean','count','std']).reset_index()
    g['sem'] = g['std'] / np.sqrt(g['count'])
    g['ci95'] = 1.96 * g['sem']
    
    # Sort by level to ensure proper order (0, 1, 2, 5, 10, 20)
    g = g.sort_values('level')

    plt.figure(figsize=(10, 6))
    bars = plt.bar(g['level'].astype(str), g['mean'], yerr=g['ci95'], capsize=4, 
                   color='steelblue', alpha=0.7, edgecolor='navy', linewidth=0.8)
    
    plt.xlabel("Packet Drop Probability (%)", fontsize=12, fontweight='bold')
    
    # Use custom ylabel if provided, otherwise use metric name
    y_label = ylabel if ylabel else metric
    if unit:
        # For bytes, show appropriate unit based on magnitude
        if unit == "bytes":
            max_val = g['mean'].max()
            if max_val >= 1024*1024:
                y_label += " (MB)"
                g['mean'] = g['mean'] / (1024*1024)
                g['ci95'] = g['ci95'] / (1024*1024)
            elif max_val >= 1024:
                y_label += " (KB)"  
                g['mean'] = g['mean'] / 1024
                g['ci95'] = g['ci95'] / 1024
            else:
                y_label += " (bytes)"
        else:
            y_label += f" ({unit})"
    
    plt.ylabel(y_label, fontsize=12, fontweight='bold')
    plt.title(title, fontsize=14, fontweight='bold', pad=20)
    
    # Show actual values on bars for clarity
    for i, (idx, row) in enumerate(g.iterrows()):
        formatted_val, display_unit = format_value_with_unit(row['mean'], unit)
        plt.text(i, row['mean'] + row['ci95'] + max(g['mean']) * 0.02, 
                f"{formatted_val}\n(n={row['count']})", 
                ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    # Professional styling
    plt.grid(True, axis='y', alpha=0.3, linestyle='--')
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(PLOTS / fname, dpi=180, bbox_inches='tight')
    plt.close()
    
    # Debug print
    print(f"✓ Generated {fname}: {len(g)} levels found: {list(g['level'])}")

def plot_comparative_cdf(df, metric_col, fname, title, xlabel):
    """Create comparative CDF plot showing all levels on the same chart"""
    if len(df) == 0:
        print(f"⚠️  Warning: Empty data for {fname}")
        return
    
    plt.figure(figsize=(10, 7))
    
    # Define colors for different levels
    colors = plt.cm.viridis(np.linspace(0, 1, len(df['level'].unique())))
    level_colors = dict(zip(sorted(df['level'].unique()), colors))
    
    # Plot CDF for each level
    for level, level_data in df.groupby('level'):
        if len(level_data) == 0:
            continue
            
        series = level_data[metric_col].dropna()
        if len(series) == 0:
            continue
            
        x = np.sort(series.values)
        y = np.arange(1, len(x)+1) / len(x)
        
        plt.plot(x, y, linewidth=2.5, alpha=0.8, color=level_colors[level],
                label=f'{level}% drop rate (n={len(series)})')
    
    plt.xlabel(xlabel, fontsize=12, fontweight='bold')
    plt.ylabel("Cumulative Distribution Function (CDF)", fontsize=12, fontweight='bold')
    plt.title(title, fontsize=14, fontweight='bold', pad=20)
    
    # Professional styling
    plt.grid(True, which='both', axis='both', alpha=0.3, linestyle='--')
    plt.gca().spines['top'].set_visible(False)
    plt.gca().spines['right'].set_visible(False)
    
    # Legend
    plt.legend(loc='lower right', frameon=True, fancybox=True, shadow=True)
    
    plt.tight_layout()
    plt.savefig(PLOTS / fname, dpi=180, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Generated comparative {fname}: {len(df['level'].unique())} levels compared")

# Generate professional bar charts with clear labels and units
plot_configs = [
    ("plt_ms", "bar_plt_ms.png", "Page Load Time vs Packet Loss", "Page Load Time", "ms"),
    ("bytes_up", "bar_bytes_up.png", "Uplink Traffic vs Packet Loss", "Bytes Transmitted (Uplink)", "bytes"),
    ("bytes_down", "bar_bytes_down.png", "Downlink Traffic vs Packet Loss", "Bytes Received (Downlink)", "bytes"), 
    ("pkt_up", "bar_pkt_up.png", "Uplink Packet Count vs Packet Loss", "Packets Transmitted (Uplink)", "packets"),
    ("pkt_down", "bar_pkt_down.png", "Downlink Packet Count vs Packet Loss", "Packets Received (Downlink)", "packets"),
    ("duration_s", "bar_duration.png", "Connection Duration vs Packet Loss", "Flow Duration", "seconds"),
]

print("Generating bar charts with professional styling...")
for metric, filename, title, ylabel, unit in plot_configs:
    if metric in summary.columns:
        agg_bar_ci(summary, metric, filename, title, ylabel, unit)
    else:
        print(f"⚠️  Warning: Metric '{metric}' not found in data")

# Generate Comparative Inter-Arrival Time CDFs
print("\nGenerating Comparative Inter-Arrival Time CDFs...")

# IAT data already has level information - no need to merge
plot_comparative_cdf(iat_up, "iat_s", "cdf_iat_uplink_comparative.png",
                    "Comparative Inter-Arrival Time Distribution - Upload Traffic",
                    "Inter-Arrival Time (seconds)")

plot_comparative_cdf(iat_down, "iat_s", "cdf_iat_downlink_comparative.png", 
                    "Comparative Inter-Arrival Time Distribution - Download Traffic",
                    "Inter-Arrival Time (seconds)")
