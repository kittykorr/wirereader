import re
import math
from datetime import datetime

def print_progress(current, total, bar_length=40):
    percent = float(current) / total
    arrow = '█' * int(round(percent * bar_length))
    spaces = ' ' * (bar_length - len(arrow))
    print(f"\r🔄 Progress: [{arrow}{spaces}] {int(percent * 100)}%", end='')


# === Prompt for log file ===
log_path = input("📄 Enter path to your human-readable log file: ").strip().strip('"')

try:
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
except FileNotFoundError:
    print(f"❌ File not found: {log_path}")
    input("🔁 Press Enter to try again...")
    exit(1)

# === Output log file ===
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_path = log_path.replace(".txt", f"_decoded_{timestamp}.txt")

print("\n🧪 Decoding Payloads...\n")

with open(output_path, "w", encoding="utf-8") as out:
    current_ts = ""
    current_src = ""
    current_dst = ""

    total_lines = len(lines)
    for i, line in enumerate(lines):
        print_progress(i + 1, total_lines)

        # Capture timestamp
        if "Packet #" in line and "Timestamp:" in line:
            ts_match = re.search(r"Timestamp: ([\d\-:\. ]+)", line)
            if ts_match:
                current_ts = ts_match.group(1)

        # Capture IP source/destination
        if "[IP]" in line:
            ip_match = re.search(r"Src IP: ([\d\.]+) → Dst IP: ([\d\.]+)", line)
            if ip_match:
                current_src = ip_match.group(1)
                current_dst = ip_match.group(2)

        
        # Decode payload
        payload_match = re.search(r"Payload.*hex.*: ([0-9a-fA-F]+)", line, re.IGNORECASE)

        if payload_match:
                hex_str = payload_match.group(1)
    raw_bytes = bytes.fromhex(hex_str)

    # Strip IP header (first 20 bytes)
    app_data = raw_bytes[20:] if len(raw_bytes) > 20 else raw_bytes

    # Entropy check
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = {b: data.count(b) for b in set(data)}
        entropy = -sum((f / len(data)) * math.log2(f / len(data)) for f in freq.values())
        return entropy

    entropy = calculate_entropy(app_data)

    # Try decompression
    def try_decompress(data: bytes) -> bytes:
        for method in ["zlib", "gzip"]:
            try:
                if method == "zlib":
                    return zlib.decompress(data)
                elif method == "gzip":
                    return gzip.decompress(data)
            except Exception:
                continue
        return data

    processed_bytes = try_decompress(app_data)

    # Try decoding
    decoded = None
    try:
        decoded = processed_bytes.decode("utf-8")
        method = "UTF-8"
    except UnicodeDecodeError:
        try:
            decoded = processed_bytes.decode("ascii")
            method = "ASCII"
        except UnicodeDecodeError:
            # Try XOR sweep
            for key in [0x00, 0xFF, 0xAA, 0x55]:
                xor_data = bytes(b ^ key for b in processed_bytes)
                try:
                    decoded = xor_data.decode("utf-8")
                    method = f"XOR key {key:#02x}"
                    break
                except:
                    continue

if not decoded:
    out.write("🔒 Payload undecodable. Raw hex:\n")
    out.write(hex_str + "\n")


    # Log output
    out.write(f"\n🧾 Packet #{i+1}\n")
    out.write(f"🕒 Timestamp: {current_ts}\n")
    out.write(f"📡 Source IP: {current_src}\n")
    out.write(f"🎯 Destination IP: {current_dst}\n")
    out.write(f"📊 Entropy: {entropy:.2f}\n")

    if decoded:
        out.write(f"🔓 Decoded ({method}):\n{decoded}\n")
    else:
        out.write("🔒 Payload: Binary or non-decodable\n")



print(f"\n✅ Decoded log saved to:\n{output_path}")
input("\n🔚 Press Enter to exit...")
