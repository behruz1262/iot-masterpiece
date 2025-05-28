import pyshark
import json
import os
from collections import defaultdict
from datetime import datetime

def analyze_pcap(pcap_path):
    cap = pyshark.FileCapture(pcap_path, only_summaries=True)
    device_counts = defaultdict(int)
    protocol_counts = defaultdict(int)
    behavior_notes = []

    for pkt in cap:
        try:
            protocol = pkt.protocol
            info = pkt.info.lower()

            # Count protocols
            protocol_counts[protocol] += 1

            # Device detection
            if 'tuya' in info or 'iot.tuya.com' in info:
                device = 'Smart Light'
            elif 'tplink' in info or 'tplinkcloud' in info:
                device = 'Smart Plug'
            elif 'samsung' in info:
                device = 'Smart TV'
            elif 'amazon' in info or 'alexa' in info:
                device = 'Smart Speaker'
            elif 'companion-link' in info or '독고철수' in info:
                device = 'Local Korean IoT'
            else:
                device = 'Unknown Device'

            device_counts[device] += 1

        except Exception:
            continue

    cap.close()

    # Write device summary
    with open("device_summary.json", "w") as f:
        json.dump(device_counts, f, indent=4)

    # Write protocol breakdown
    with open("protocol_breakdown.json", "w") as f:
        json.dump(protocol_counts, f, indent=4)

    # Write behavior analysis
    for dev, count in device_counts.items():
        if count > 300:
            behavior = f"⚠️ {dev} is VERY chatty! ({count} packets)"
        elif count > 50:
            behavior = f"🟡 {dev} is moderately active ({count} packets)"
        else:
            behavior = f"🟢 {dev} is mostly quiet ({count} packets)"
        behavior_notes.append(behavior)

    with open("behavior_notes.txt", "w") as f:
        f.write("\n".join(behavior_notes))

    print("✅ Analysis complete. 3 files saved:")
    print(" - device_summary.json")
    print(" - protocol_breakdown.json")
    print(" - behavior_notes.txt")

if __name__ == "__main__":
    pcap_file = input("📂 Enter the full path to your .pcap file:\n> ")
    analyze_pcap(pcap_file.strip())

