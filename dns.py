import socket
import random
import struct

ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "199.9.14.201",    # b.root-servers.net
    "192.33.4.12",     # c.root-servers.net
    "199.7.91.13",     # d.root-servers.net
    "192.203.230.10",  # e.root-servers.net
    "192.5.5.241",     # f.root-servers.net
    "192.112.36.4",    # g.root-servers.net
    "198.97.190.53",   # h.root-servers.net
    "192.36.148.17",   # i.root-servers.net
    "192.58.128.30",   # j.root-servers.net
    "193.0.14.129",    # k.root-servers.net
    "199.7.83.42",     # l.root-servers.net
    "202.12.27.33"     # m.root-servers.net
]

def build_query_packet(domain):
    # --- Header ---
    tid = random.randint(0, 65535)          # Transaction ID
    flags = 0x0100                           # Standard query, recursion desired = 1
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH",
                         tid, flags, qdcount,
                         ancount, nscount, arcount)

    # --- Question section ---
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part))
        qname += part.encode()
    qname += b"\x00"   # end of name

    qtype = 1          # A record
    qclass = 1         # IN (internet)

    question = qname + struct.pack(">HH", qtype, qclass)

    return header + question, tid


def send_query(server, packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(packet, (server, 53))
    data, _ = sock.recvfrom(512)    # standard DNS packet size
    sock.close()
    return data


def main():
    domain = "cs.fiu.edu"
    current_server = ROOT_SERVERS[-1]   # m.root-servers.net (as in sample output)

    print("Querying domain:", domain)

    # Build the query once
    packet, tid = build_query_packet(domain)

    print("Sending packet to:", current_server)
    response = send_query(current_server, packet)

    print("Received", len(response), "bytes")
    print("Raw response (hex):")
    print(response.hex())


if __name__ == "__main__":
    main()
