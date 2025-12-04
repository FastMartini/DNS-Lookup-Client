# DNS-Lookup-Client

This project implements a fully functional DNS Lookup Client using raw UDP socket programming in Python.
The resolver performs DNS lookups manually, without relying on external DNS libraries, following the true iterative resolution process used by real DNS resolvers.

The program sends a DNS query to a root DNS server, processes the reply, extracts the next DNS server to query, and continues step-by-step through the DNS hierarchy until the final authoritative DNS server returns the IP address for the target domain.

The client supports:

- Constructing raw DNS query packets

- Parsing DNS responses (header, question, answer, authority, additional sections)

- Handling DNS name compression

- Iteratively querying root, TLD, and authoritative DNS servers

- Displaying server replies at each hop

- Extracting intermediate DNS server IPs from NS + Additional records

- Displaying final A-record results for the queried domain

The project uses only socket programming concepts, with no external DNS or FTP libraries allowed, fully aligning with network protocol-level learning objectives.

# How it Works

1. The client sends a DNS query to a specified root DNS server.

2. The root server returns referral information for the appropriate TLD (e.g., .edu).

3. The client extracts the next DNS server IP and sends a new query.

4. This continues until the authoritative server returns the domain’s A record.

5. The client prints all responses for visibility and grading requirements.

# Usage

    python3 mydns.py <domain-name> <root-dns-ip>

Example:

    python3 mydns.py cs.fiu.edu 202.12.27.33


