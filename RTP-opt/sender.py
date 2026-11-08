import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
MAX_PAYLOAD = 1456
TIMEOUT = 0.5
HEADER_LEN = 16
HANDSHAKE_TRIES = 50


def create_packet(kind, seq, content=b""):
    header = PacketHeader(type=kind, seq_num=seq, length=len(content))
    header.checksum = compute_checksum(header / content)
    return bytes(header / content)


def decode(raw):
    if len(raw) < HEADER_LEN:
        return None
    header = PacketHeader(raw[:HEADER_LEN])
    body = raw[HEADER_LEN:HEADER_LEN + header.length]
    claimed = header.checksum
    header.checksum = 0
    if compute_checksum(header / body) != claimed:
        return None
    return header.type, header.seq_num


class Link:
    def __init__(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect((ip, port))

    def transmit(self, packet):
        self.sock.send(packet)

    def listen(self, wait):
        if wait <= 0:
            return None
        self.sock.settimeout(wait)
        try:
            return decode(self.sock.recv(2048))
        except socket.timeout:
            return None
        except ConnectionResetError:
            time.sleep(0.01)
            return None

    def close(self):
        self.sock.close()

def handshake(link, kind, seq, expected_ack):
    packet = create_packet(kind, seq)
    for _ in range(HANDSHAKE_TRIES):
        link.transmit(packet)
        limit = time.monotonic() + TIMEOUT
        while True:
            left = limit - time.monotonic()
            if left <= 0:
                break
            if link.listen(left) == (ACK, expected_ack):
                return True
    return False
def finish(link, end_seq):
    link.transmit(create_packet(END, end_seq))
    limit = time.monotonic() + TIMEOUT
    while True:
        left = limit - time.monotonic()
        if left <= 0:
            return False
        if link.listen(left) == (ACK, end_seq + 1):
            return True


class WindowSender:
    def __init__(self, link, packets, window):
        self.acked = [False] * len(packets)
        self.link = link
        self.packets = packets
        self.window = window
        self.base = 0
        self.nxt = 0
        self.deadline = 0.0

    def fill_window(self):
        while self.nxt < self.base + self.window and self.nxt < len(self.packets):
            if self.base == self.nxt:
                self.deadline = time.monotonic() + TIMEOUT
            self.link.transmit(self.packets[self.nxt])
            self.nxt += 1

    def on_ack(self, ack_seq):
        index = ack_seq - 1
        if not (self.base <= index < self.nxt):
            return

        self.acked[index] = True

        old_base = self.base
        while self.base < self.nxt and self.acked[self.base]:
            self.base += 1

        if self.base != old_base and self.base < self.nxt:
            self.deadline = time.monotonic() + TIMEOUT

    def retransmit(self):
        for i in range(self.base, self.nxt):
            if not self.acked[i]:
                self.link.transmit(self.packets[i])
        self.deadline = time.monotonic() + TIMEOUT
    def run(self):
        while self.base < len(self.packets):
            self.fill_window()
            reply = self.link.listen(self.deadline - time.monotonic())
            if reply and reply[0] == ACK:
                self.on_ack(reply[1])
            if time.monotonic() >= self.deadline:
                self.retransmit()


def sender(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        print("window_size phải lớn hơn 0", file=sys.stderr)
        return
    payload = sys.stdin.buffer.read()
    pieces = [payload[i:i + MAX_PAYLOAD] for i in range(0, len(payload), MAX_PAYLOAD)]
    packets = [create_packet(DATA, n, piece) for n, piece in enumerate(pieces, start=1)]

    end_seq = len(packets) + 1
    link = Link(receiver_ip, receiver_port)
    try:
        if not handshake(link, START, 0, 1):
            print("Không nhận được ACK cho START", file=sys.stderr)
            return

        WindowSender(link, packets, window_size).run()
        finish(link, end_seq)
    finally:
        link.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()