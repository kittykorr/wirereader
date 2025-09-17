# python CLI pcap/wireshark dump parser, exports human readable logs

from scapy.all import rdpcap, Ether, IP, TCP, UDP, ARP, DNS, DNSQR
from datetime import datetime
import os
import time
import sys

# === Output directory ===

# put your filepath here
log_dir = r"ADD YOUR FILEPATH HERE"
# change above filepath

os.makedirs(log_dir, exist_ok=True)

def format_timestamp(pkt):
    return datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')

def show_progress(current, total, start):
    percent = (current / total) * 100
    elapsed = time.time() - start
    est_total = (elapsed / current) * total if current > 0 else 0
    remaining = est_total - elapsed
    bar_len = 40
    filled_len = int(bar_len * current // total)
    bar = '█' * filled_len + '-' * (bar_len - filled_len)
    print(f"\rProgress: |{bar}| {percent:6.2f}% ⏱️ ETA: {remaining:5.1f}s", end='')

def parse_pcap(pcap_path):
    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"❌ File not found: {pcap_path}")
        return

    total_packets = len(packets)
    start_time = time.time()

    # Create log file with timestamp
    base_name = os.path.basename(pcap_path).replace(".pcap", "").replace(".pcapng", "")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"{base_name}_log_{timestamp}.txt")

    with open(log_file, "w", encoding="utf-8") as f:
        for i, pkt in enumerate(packets, start=1):
            ts = format_timestamp(pkt)
            f.write(f"\nPacket #{i} | Timestamp: {ts}\n")

            if Ether in pkt:
                f.write(f"  [Ether] Src MAC: {pkt[Ether].src} → Dst MAC: {pkt[Ether].dst}\n")

            if ARP in pkt:
                op = "Request" if pkt[ARP].op == 1 else "Reply"
                f.write(f"  [ARP] {op}: {pkt[ARP].psrc} → {pkt[ARP].pdst}\n")

            if IP in pkt:
                proto = pkt[IP].proto
                f.write(f"  [IP] Src IP: {pkt[IP].src} → Dst IP: {pkt[IP].dst} | Protocol: {proto}\n")

                if TCP in pkt:
                    flags = pkt[TCP].flags
                    f.write(f"  [TCP] {pkt[IP].src}:{pkt[TCP].sport} → {pkt[IP].dst}:{pkt[TCP].dport} | Flags: {flags}\n")
                    f.write(f"        Seq: {pkt[TCP].seq} Ack: {pkt[TCP].ack} Win: {pkt[TCP].window} Len: {len(pkt[TCP].payload)}\n")

                elif UDP in pkt:
                    f.write(f"  [UDP] {pkt[IP].src}:{pkt[UDP].sport} → {pkt[IP].dst}:{pkt[UDP].dport} | Len: {len(pkt[UDP].payload)}\n")

            if DNS in pkt and DNSQR in pkt:
                qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
                f.write(f"  [DNS] Query: {qname} | Type: {pkt[DNSQR].qtype}\n")

            raw_bytes = bytes(pkt.payload)
            if raw_bytes and len(raw_bytes) > 0:
                full_payload_hex = raw_bytes.hex()
                f.write(f"  [Payload] Full (hex): {full_payload_hex}\n")


            show_progress(i, total_packets, start_time)

    print(f"\n\n✅ Parsing complete.")
    print(f"📄 Log saved to: {log_file}\n")

# === Interactive Loop ===
print("\n" + "="*50)
print("🛠️  Make Wireshark Readable Again")
print("="*50 + "\n")

while True:
    pcap_path = input("📁 Enter path to .pcap file (or type 'exit' to quit): ").strip()
    if pcap_path.lower() == "exit":
        print("\n👋 Exiting parser. Stay stealthy, User.")
        break
    parse_pcap(pcap_path)

input("\n🔚 Press Enter to continue or type 'exit' to close: ")

