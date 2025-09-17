import re

line = "[Payload] Full (hex): 48656c6c6f205776f726c6421"

# This line must be typed exactly as shown-no line breaks, no extra spaces
match = re.search(r"\[Payload\] Full \(hex\): ([0-9a-fa-F]+)", line)

                  if match:
                      hex_str = match.group(1)
                      raw_bytes = bytes.fromhex(hex_str)
                      try:
                          decoded = raw_bytes.decode("utf-8")
                          print(f"Decoded (UTF-8): {decoded}")
                      except UnicodeDecodeError:
                          print("Binary or non-decodable")
