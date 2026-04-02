"""
Protocol Server – Multi-command dispatcher for hybrid inference testing.

Binary protocol format (big-endian):
  ┌──────────┬──────────┬───────┬────────────────────┐
  │ CMD (1B) │ FLAGS(1B)│LEN(2B)│   PAYLOAD (LEN B)  │
  └──────────┴──────────┴───────┴────────────────────┘

Commands:
  0x01 ECHO   — echoes payload back
  0x02 UPPER  — returns payload uppercased
  0x03 LOWER  — returns payload lowercased
  0x04 REV    — returns payload reversed
  0x05 STATS  — returns len + byte frequency counts
  0x06 PING   — returns PONG (ignores payload)
  0x07 TIME   — returns server timestamp

Flags (bitmask):
  0x01 — request server ACK before response
  0x02 — request hex-encoded response

The server processes multiple messages per connection and dispatches
based on CMD byte, exercising different code paths for each command.
"""
import socket
import struct
import time
import json

HOST = '127.0.0.1'
PORT = 12345

# --- Protocol constants ---
CMD_ECHO  = 0x01
CMD_UPPER = 0x02
CMD_LOWER = 0x03
CMD_REV   = 0x04
CMD_STATS = 0x05
CMD_PING  = 0x06
CMD_TIME  = 0x07

FLAG_ACK = 0x01
FLAG_HEX = 0x02

HEADER_SIZE = 4  # cmd(1) + flags(1) + length(2)


def build_response(cmd, flags, payload_bytes):
    """Dispatch based on cmd byte — each branch is a different execution path."""
    if cmd == CMD_ECHO:
        result = payload_bytes

    elif cmd == CMD_UPPER:
        result = payload_bytes.upper()

    elif cmd == CMD_LOWER:
        result = payload_bytes.lower()

    elif cmd == CMD_REV:
        result = payload_bytes[::-1]

    elif cmd == CMD_STATS:
        freq = {}
        for b in payload_bytes:
            freq[b] = freq.get(b, 0) + 1
        body = json.dumps({
            "length": len(payload_bytes),
            "unique_bytes": len(freq),
            "top_byte": max(freq, key=freq.get) if freq else 0,
        }).encode()
        result = body

    elif cmd == CMD_PING:
        result = b"PONG"

    elif cmd == CMD_TIME:
        result = str(time.time()).encode()

    else:
        result = b"ERR:UNKNOWN_CMD"

    # Apply flags
    if flags & FLAG_HEX:
        result = result.hex().encode()

    return result


def recv_exact(conn, n):
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def handle_client(conn, addr):
    print(f"[*] Connected by {addr}")
    msg_count = 0

    while True:
        # Read the 4-byte header
        header = recv_exact(conn, HEADER_SIZE)
        if header is None:
            break

        cmd, flags, payload_len = struct.unpack('!BBH', header)
        msg_count += 1

        # Read payload
        payload = b""
        if payload_len > 0:
            payload = recv_exact(conn, payload_len)
            if payload is None:
                break

        print(f"  [{msg_count}] cmd=0x{cmd:02x} flags=0x{flags:02x} "
              f"len={payload_len} payload={payload[:32]}...")

        # Send ACK if requested
        if flags & FLAG_ACK:
            conn.sendall(b"\x00\x01")  # 2-byte ACK

        # Build and send response
        response_body = build_response(cmd, flags, payload)
        # Response format: LEN(2B) + BODY
        resp_header = struct.pack('!H', len(response_body))
        conn.sendall(resp_header + response_body)

    print(f"[*] Client disconnected after {msg_count} messages.")


print(f"[*] Protocol server starting on {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print("[*] Server is listening...")

    conn, addr = s.accept()
    with conn:
        handle_client(conn, addr)

print("[*] Server shutting down.")