#!/usr/bin/env python3
"""Fake public host for the e2e tests: reports the source address it sees.

    web.py ADDR HTTP_PORT UDP_PORT BLOB [DNS_PORT]

HTTP `GET /whoami...` returns the client IP, `GET /blob` returns the BLOB file. Every UDP
datagram is answered with the sender's IP. With DNS_PORT, a DNS server answers every A query
with the sender's IP too.
"""

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main() -> None:
    addr, http_port, udp_port, blob_path = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    blob = open(blob_path, "rb").read()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/whoami"):
                body = self.client_address[0].encode()
            elif self.path == "/blob":
                body = blob
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            sys.stderr.write(f"{self.client_address[0]} {fmt % args}\n")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((addr, udp_port))

    def echo():
        while True:
            _, peer = udp.recvfrom(65535)
            udp.sendto(peer[0].encode(), peer)

    threading.Thread(target=echo, daemon=True).start()
    if len(sys.argv) > 5:
        threading.Thread(target=dns, args=(addr, int(sys.argv[5])), daemon=True).start()
    ThreadingHTTPServer((addr, http_port), Handler).serve_forever()


def dns(addr: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((addr, port))
    while True:
        query, peer = sock.recvfrom(512)
        end = 12
        while query[end]:
            end += query[end] + 1
        question = query[12 : end + 5]
        answer = b""
        if question[-4:-2] == b"\x00\x01":  # QTYPE A
            # Name pointer to the question, type A, class IN, TTL 0, 4-byte address.
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + socket.inet_aton(peer[0])
        header = query[:2] + b"\x81\x80\x00\x01" + (b"\x00\x01" if answer else b"\x00\x00") + b"\x00\x00\x00\x00"
        sock.sendto(header + question + answer, peer)
        sys.stderr.write(f"{peer[0]} DNS query\n")


if __name__ == "__main__":
    main()
