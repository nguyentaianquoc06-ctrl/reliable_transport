import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
HEADER_LEN = 16


def create_packet(kind, seq_num, payload=b""):
    header = PacketHeader(type=kind, seq_num=seq_num, length=len(payload))
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def decode_packet(raw):
    if len(raw) < HEADER_LEN:
        return None

    header = PacketHeader(raw[:HEADER_LEN])
    if len(raw) != HEADER_LEN + header.length:
        return None

    payload = raw[HEADER_LEN:]
    claimed_checksum = header.checksum
    header.checksum = 0
    if compute_checksum(header / payload) != claimed_checksum:
        return None

    return header.type, header.seq_num, payload


def receiver(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        print("window_size phải lớn hơn 0", file=sys.stderr)
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((receiver_ip, receiver_port))
        active = False
        sender_address = None
        expected = 0
        buffered = {}

        while True:
            raw, address = sock.recvfrom(2048)
            packet = decode_packet(raw)
            if packet is None:
                continue

            kind, seq_num, payload = packet
            if kind not in (START, END, DATA) or payload and kind != DATA:
                continue

            if kind == START:
                if active or seq_num != 0:
                    continue
                active = True
                sender_address = address
                expected = 1
                buffered.clear()
                sock.sendto(create_packet(ACK, expected), address)
                continue

            if not active or address != sender_address:
                continue

            if kind == DATA:
                if expected <= seq_num < expected + window_size:
                    buffered.setdefault(seq_num, payload)

                    while expected in buffered:
                        sys.stdout.buffer.write(buffered.pop(expected))
                        expected += 1
                    sys.stdout.buffer.flush()

                sock.sendto(create_packet(ACK, expected), address)
                continue

            if kind == END:
                if seq_num == expected:
                    sock.sendto(create_packet(ACK, seq_num + 1), address)
                    return
                sock.sendto(create_packet(ACK, expected), address)
    finally:
        sock.close()


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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
