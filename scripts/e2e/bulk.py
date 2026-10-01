#!/usr/bin/env python3
"""Bulk TCP transfers for throughput measurements, and a long-lived TCP conversation.

    bulk.py serve ADDR PORT
    bulk.py up|down HOST PORT SECONDS
    bulk.py chat HOST PORT STOPFILE

`up` streams to the server for SECONDS and prints the Mbit/s the server actually received;
`down` has the server stream for SECONDS and prints the Mbit/s received. `chat` sends a
numbered line every 100 ms over one connection and checks every echo, until STOPFILE exists;
it exits 0 only if the connection survived and every line came back in order.
"""

import os
import socket
import struct
import sys
import threading
import time

CHUNK = b"\0" * 65536


def serve(addr: str, port: int) -> None:
    srv = socket.create_server((addr, port), reuse_port=True)

    def handle(conn: socket.socket) -> None:
        with conn:
            mode = conn.recv(1)
            if mode == b"u":
                total = 0
                while data := conn.recv(1 << 20):
                    total += len(data)
                conn.sendall(str(total).encode())
            elif mode == b"d":
                (seconds,) = struct.unpack("!d", conn.recv(8))
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    conn.sendall(CHUNK)
            elif mode == b"e":
                while data := conn.recv(65536):
                    conn.sendall(data)

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def up(host: str, port: int, seconds: float) -> float:
    s = socket.create_connection((host, port), timeout=seconds + 30)
    s.sendall(b"u")
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        s.sendall(CHUNK)
    s.shutdown(socket.SHUT_WR)
    total = int(s.recv(64).decode())
    return total * 8 / (time.monotonic() - start) / 1e6


def down(host: str, port: int, seconds: float) -> float:
    s = socket.create_connection((host, port), timeout=seconds + 30)
    s.sendall(b"d" + struct.pack("!d", seconds))
    start = time.monotonic()
    total = 0
    while data := s.recv(1 << 20):
        total += len(data)
    return total * 8 / (time.monotonic() - start) / 1e6


def chat(host: str, port: int, stopfile: str) -> int:
    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(None)
    s.sendall(b"e")
    state = {"echoed": 0, "error": None}

    def read() -> None:
        buf = b""
        try:
            while data := s.recv(4096):
                buf += data
                *lines, buf = buf.split(b"\n")
                for line in lines:
                    if int(line) != state["echoed"]:
                        raise ValueError(f"echo {int(line)} out of order")
                    state["echoed"] += 1
            state["error"] = "connection closed"
        except (OSError, ValueError) as e:
            state["error"] = str(e)

    threading.Thread(target=read, daemon=True).start()
    sent = 0
    while not os.path.exists(stopfile) and state["error"] is None:
        s.sendall(f"{sent}\n".encode())
        sent += 1
        time.sleep(0.1)
    deadline = time.monotonic() + 30
    while state["echoed"] < sent and state["error"] is None and time.monotonic() < deadline:
        time.sleep(0.1)
    print(f"sent {sent}, echoed {state['echoed']}, error {state['error']}")
    return 0 if state["echoed"] == sent and state["error"] is None else 1


def main() -> None:
    cmd = sys.argv[1]
    if cmd == "serve":
        serve(sys.argv[2], int(sys.argv[3]))
    elif cmd == "chat":
        sys.exit(chat(sys.argv[2], int(sys.argv[3]), sys.argv[4]))
    else:
        fn = {"up": up, "down": down}[cmd]
        print(f"{fn(sys.argv[2], int(sys.argv[3]), float(sys.argv[4])):.0f}")


if __name__ == "__main__":
    main()
