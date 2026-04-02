"""
Protocol Client – Generates diverse structured traffic for analysis.

Sends 60+ messages using the binary protocol format:
  CMD(1B) | FLAGS(1B) | LEN(2B) | PAYLOAD(LEN B)

Covers all 7 command types with varying payloads, flags, and lengths
to produce enough variability for meaningful clustering/alignment.
"""
import socket
import struct
import time
import random
import string

HOST = '127.0.0.1'
PORT = 12345

# --- Commands ---
CMD_ECHO  = 0x01
CMD_UPPER = 0x02
CMD_LOWER = 0x03
CMD_REV   = 0x04
CMD_STATS = 0x05
CMD_PING  = 0x06
CMD_TIME  = 0x07

FLAG_ACK = 0x01
FLAG_HEX = 0x02


def rand_ascii(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n)).encode()


def send_msg(sock, cmd, flags, payload):
    """Send one protocol message and receive the response."""
    header = struct.pack('!BBH', cmd, flags, len(payload))
    sock.sendall(header + payload)

    # Read ACK if we requested it
    if flags & FLAG_ACK:
        ack = sock.recv(2)
        assert ack == b"\x00\x01", f"Bad ACK: {ack}"

    # Read response: LEN(2B) + BODY
    resp_hdr = sock.recv(2)
    if len(resp_hdr) < 2:
        return b""
    resp_len = struct.unpack('!H', resp_hdr)[0]
    body = b""
    while len(body) < resp_len:
        chunk = sock.recv(resp_len - len(body))
        if not chunk:
            break
        body += chunk
    return body


def generate_messages():
    """Build a diverse set of messages exercising all commands and flag combos."""
    messages = []

    # ── ECHO variants — different payload sizes ──
    for size in [4, 8, 16, 32, 64, 128]:
        messages.append((CMD_ECHO, 0x00, rand_ascii(size)))
    # ECHO with ACK flag
    for _ in range(3):
        messages.append((CMD_ECHO, FLAG_ACK, rand_ascii(random.randint(8, 48))))
    # ECHO with HEX flag
    for _ in range(3):
        messages.append((CMD_ECHO, FLAG_HEX, rand_ascii(random.randint(8, 32))))

    # ── UPPER — text payloads ──
    texts = [b"hello world", b"SLPH Protocol Analyzer", b"test message 123",
             b"the quick brown fox", b"aaBBccDDee"]
    for t in texts:
        messages.append((CMD_UPPER, 0x00, t))
    for _ in range(3):
        messages.append((CMD_UPPER, FLAG_ACK | FLAG_HEX, rand_ascii(random.randint(10, 30))))

    # ── LOWER — text payloads ──
    for t in [b"HELLO WORLD", b"SLPH MVP", b"BINARY TRACER", b"NETWORK ANALYSIS"]:
        messages.append((CMD_LOWER, 0x00, t))
    messages.append((CMD_LOWER, FLAG_HEX, b"MIXED Case Text"))

    # ── REV — varying payload ──
    for _ in range(5):
        messages.append((CMD_REV, 0x00, rand_ascii(random.randint(5, 50))))
    messages.append((CMD_REV, FLAG_ACK, b"reverse me please"))

    # ── STATS — binary payloads with varied byte distributions ──
    messages.append((CMD_STATS, 0x00, bytes(range(256))))        # all bytes
    messages.append((CMD_STATS, 0x00, b"\x00" * 64))             # uniform
    messages.append((CMD_STATS, 0x00, rand_ascii(100)))          # random ascii
    messages.append((CMD_STATS, FLAG_ACK, bytes([0xAA, 0xBB, 0xCC] * 20)))

    # ── PING — no payload needed ──
    for _ in range(6):
        flags = random.choice([0x00, FLAG_ACK])
        messages.append((CMD_PING, flags, b""))

    # ── TIME — timestamp requests ──
    for _ in range(5):
        messages.append((CMD_TIME, 0x00, b""))
    messages.append((CMD_TIME, FLAG_HEX, b""))

    # ── Fill to ~60+ messages with random commands ──
    all_cmds = [CMD_ECHO, CMD_UPPER, CMD_LOWER, CMD_REV, CMD_STATS, CMD_PING, CMD_TIME]
    while len(messages) < 60:
        cmd = random.choice(all_cmds)
        flags = random.choice([0x00, FLAG_ACK, FLAG_HEX, FLAG_ACK | FLAG_HEX])
        payload = rand_ascii(random.randint(4, 80)) if cmd not in (CMD_PING, CMD_TIME) else b""
        messages.append((cmd, flags, payload))

    # Shuffle for realistic interleaving
    random.shuffle(messages)
    return messages


def main():
    time.sleep(1)  # wait for server startup
    print(f"[*] Client connecting to {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        messages = generate_messages()
        print(f"[*] Sending {len(messages)} messages...")

        for i, (cmd, flags, payload) in enumerate(messages, 1):
            try:
                resp = send_msg(s, cmd, flags, payload)
                print(f"  [{i:3d}] cmd=0x{cmd:02x} flags=0x{flags:02x} "
                      f"len={len(payload):4d} → resp={len(resp)} bytes")
            except Exception as e:
                print(f"  [{i:3d}] ERROR: {e}")
                break

            # Small delay between some messages for realistic timing
            if random.random() < 0.1:
                time.sleep(0.05)

    print(f"[*] Client finished. Sent {len(messages)} messages.")


if __name__ == '__main__':
    main()