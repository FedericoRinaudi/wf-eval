#!/usr/bin/env python3
"""
Generate test CSV data to verify plotting functionality
Simulates complete experiment results with all levels and realistic data
"""
import pandas as pd
import numpy as np
from pathlib import Path

# Configuration
OUT = Path("test_data")
OUT.mkdir(parents=True, exist_ok=True)

# Set random seed for reproducible test data
np.random.seed(42)

# URLs from your urls.txt (simulated)
urls = [
    "https://www.google.com",
    "https://www.youtube.com", 
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.netflix.com",
    "https://www.apple.com",
    "https://www.microsoft.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.linkedin.com"
]

# Experiment configuration
levels = [0, 1, 2, 5, 10, 20]  # Drop probability levels
reps = 10  # Repetitions per level
urls_count = len(urls)

print(f"Generating test data for {len(levels)} levels, {reps} reps, {urls_count} URLs")
print(f"Total expected records: {len(levels)} × {reps} × {urls_count} = {len(levels) * reps * urls_count}")

# ================================================================
# Generate summary.csv (main metrics)
# ================================================================
summary_data = []

for level in levels:
    for rep in range(1, reps + 1):
        for url in urls:
            # Simulate realistic metrics with packet loss effects
            
            # Base PLT increases with packet loss (realistic effect)
            base_plt = np.random.normal(1500, 300)  # Base ~1.5s ± 300ms
            plt_increase = level * 50  # +50ms per 1% loss
            plt_ms = max(base_plt + plt_increase + np.random.normal(0, 100), 500)
            
            # Bytes: slightly decrease with more retransmissions due to losses
            base_bytes_up = np.random.normal(50000, 10000)  # ~50KB up
            base_bytes_down = np.random.normal(500000, 100000)  # ~500KB down
            bytes_up = max(base_bytes_up * (1 + level * 0.02), 10000)  # +2% per level
            bytes_down = max(base_bytes_down * (1 + level * 0.02), 50000)
            
            # Packets: increase with retransmissions
            pkt_up = max(int(bytes_up / 1400 * (1 + level * 0.05)), 10)  # +5% per level  
            pkt_down = max(int(bytes_down / 1400 * (1 + level * 0.05)), 30)
            
            # Duration: increases with packet loss (more retransmissions)
            base_duration = np.random.normal(8, 2)  # ~8s ± 2s
            duration_s = max(base_duration + level * 0.3, 2)  # +0.3s per level
            
            summary_data.append({
                "url": url,
                "level": level, 
                "rep": rep,
                "pcap": f"fake_lvl{level}_rep{rep}_{url.replace('://', '_').replace('/', '_')}.pcap",
                "plt_ms": round(plt_ms, 2),
                "bytes_up": int(bytes_up),
                "bytes_down": int(bytes_down),
                "pkt_up": pkt_up,
                "pkt_down": pkt_down,
                "duration_s": round(duration_s, 2)
            })

summary_df = pd.DataFrame(summary_data)
summary_df.to_csv(OUT / "summary.csv", index=False)
print(f"✓ Generated summary.csv with {len(summary_df)} records")
print(f"  Levels: {sorted(summary_df['level'].unique())}")
print(f"  Level counts: {dict(summary_df['level'].value_counts().sort_index())}")

# ================================================================
# Generate iat_up.csv and iat_down.csv (Inter-Arrival Times)
# ================================================================
def generate_iat_data(direction_name):
    """Generate realistic Inter-Arrival Time data"""
    iat_data = []
    
    for level in levels:
        for rep in range(1, reps + 1):
            for url in urls:
                # Generate realistic IAT distribution
                # Higher packet loss → more variable timing
                base_iat = 0.001  # 1ms base
                variability = 1 + level * 0.1  # More variable with loss
                
                # Generate 20-100 IAT samples per flow
                n_packets = np.random.randint(20, 100)
                
                for _ in range(n_packets):
                    # Exponential distribution for IAT (realistic)
                    iat_s = np.random.exponential(base_iat * variability)
                    iat_s = min(iat_s, 1.0)  # Cap at 1 second
                    
                    iat_data.append({
                        "url": url,
                        "level": level,
                        "rep": rep, 
                        "iat_s": round(iat_s, 6)
                    })
    
    return pd.DataFrame(iat_data)

# Generate uplink and downlink IAT data
iat_up_df = generate_iat_data("up")
iat_down_df = generate_iat_data("down")

iat_up_df.to_csv(OUT / "iat_up.csv", index=False)
iat_down_df.to_csv(OUT / "iat_down.csv", index=False)

print(f"✓ Generated iat_up.csv with {len(iat_up_df)} IAT records")
print(f"✓ Generated iat_down.csv with {len(iat_down_df)} IAT records")

# ================================================================
# Summary statistics for verification
# ================================================================
print("\n" + "="*50)
print("TEST DATA SUMMARY")
print("="*50)

for level in levels:
    level_data = summary_df[summary_df['level'] == level]
    plt_mean = level_data['plt_ms'].mean()
    plt_std = level_data['plt_ms'].std()
    print(f"Level {level:2d}%: PLT = {plt_mean:6.1f} ± {plt_std:5.1f} ms (n={len(level_data)})")

print(f"\nFiles generated in {OUT}:")
print(f"  - summary.csv ({len(summary_df)} records)")
print(f"  - iat_up.csv ({len(iat_up_df)} records)")  
print(f"  - iat_down.csv ({len(iat_down_df)} records)")
print("\nReady to test plot_results.py!")
