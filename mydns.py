#!/usr/bin/env python3  # Shebang line so the script can be executed directly on Unix-like systems

import socket          # Import the socket module to create UDP sockets
import struct          # Import struct for packing and unpacking binary data
import random          # Import random to generate transaction IDs for DNS queries
import sys             # Import sys to read command-line arguments and exit if needed


def build_dns_query(domain_name):  # Define a function that builds a DNS query message for a given domain name
    transaction_id = random.getrandbits(16)  # Generate a random 16-bit transaction ID for the DNS query
    flags = 0x0100                           # Set flags to standard query with recursion desired (0x0100)
    qdcount = 1                              # Set the number of questions to 1
    ancount = 0                              # Set the number of answer RRs to 0 for the query
    nscount = 0                              # Set the number of authority RRs to 0 for the query
    arcount = 0                              # Set the number of additional RRs to 0 for the query

    header = struct.pack(">HHHHHH",         # Pack the DNS header fields into network byte order (big-endian)
                         transaction_id,    # Pack the transaction ID
                         flags,            # Pack the flags field
                         qdcount,          # Pack the number of questions
                         ancount,          # Pack the number of answer RRs
                         nscount,          # Pack the number of authority RRs
                         arcount)          # Pack the number of additional RRs

    qname_parts = domain_name.split(".")    # Split the domain name into labels by the dot character
    qname_bytes = b""                       # Initialize a bytes object that will hold the encoded QNAME

    for label in qname_parts:               # Loop over each label in the domain name
        length = len(label)                 # Compute the length of the current label
        qname_bytes += struct.pack("B", length)  # Append the length byte for the label
        qname_bytes += label.encode("ascii")     # Append the ASCII-encoded characters of the label

    qname_bytes += b"\x00"                  # Append a zero-length byte to mark the end of the QNAME

    qtype = 1                               # Set the query type to 1 (A record)
    qclass = 1                              # Set the query class to 1 (IN, the Internet)

    question = qname_bytes + struct.pack(">HH", qtype, qclass)  # Build the question section by concatenating QNAME, QTYPE, and QCLASS

    full_query = header + question          # Concatenate the header and question to form the full DNS query message

    return transaction_id, full_query       # Return the transaction ID and the packed DNS query


def parse_name(message, offset):            # Define a function to decode a domain name that may use compression
    labels = []                             # Initialize a list to store the decoded labels of the domain name
    original_offset = offset                # Store the original offset for later use when following compression pointers
    jumped = False                          # Track whether a compression jump has occurred

    while True:                             # Continue reading bytes until the terminator is found
        length = message[offset]            # Read the next length byte from the message

        if length & 0xC0 == 0xC0:           # Check if the two highest bits are set, indicating a compression pointer
            pointer = ((length & 0x3F) << 8) | message[offset + 1]  # Compute the 14-bit pointer to the actual name location
            offset += 2                     # Move the current offset past the pointer bytes
            if not jumped:                  # If this is the first jump
                original_offset = offset    # Save where parsing should continue after resolving the name
            offset = pointer                # Jump to the pointer position to continue reading the name
            jumped = True                   # Mark that a jump has occurred
        elif length == 0:                   # If length is zero, the end of the name has been reached
            offset += 1                     # Move past the zero-length terminator byte
            break                           # Stop reading labels
        else:                               # Handle a normal label with a non-zero length
            offset += 1                     # Move to the first character of the label
            label = message[offset:offset + length].decode("ascii")  # Decode the label characters from ASCII
            labels.append(label)            # Append the decoded label to the list
            offset += length                # Move the offset past this label

    decoded_name = ".".join(labels)         # Join all labels with dots to reconstruct the full domain name

    if jumped:                              # If a compression jump occurred
        return decoded_name, original_offset  # Return the name and the offset after the original compressed field
    else:                                   # If no compression jump occurred
        return decoded_name, offset         # Return the name and the offset immediately after the name


def parse_resource_records(message, count, offset):  # Define a function to parse a list of resource records
    records = []                                   # Initialize a list to store parsed resource record dictionaries

    for _ in range(count):                         # Loop once for each resource record indicated by the count
        name, offset = parse_name(message, offset) # Decode the owner name and get the new offset
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", message[offset:offset + 10])  # Unpack the fixed RR header
        offset += 10                               # Move past the fixed part of the RR header
        rdata_start = offset                       # Record the start offset of the RDATA field

        if rtype == 1 and rdlength == 4:           # If the RR is an A record with a 4-byte IPv4 address
            rdata_bytes = message[offset:offset + 4]  # Extract the 4 bytes representing the IPv4 address
            ip_parts = [str(b) for b in rdata_bytes]  # Convert each byte to its decimal string representation
            rdata = ".".join(ip_parts)             # Join the decimal parts with dots to form the IPv4 address
        elif rtype == 2:                           # If the RR is an NS record
            rdata, _ = parse_name(message, offset) # Decode the domain name of the name server from the RDATA field
        else:                                      # For other record types not explicitly needed
            rdata = message[offset:offset + rdlength]  # Store the raw RDATA bytes for completeness

        offset = rdata_start + rdlength            # Move the offset past the RDATA field

        record = {                                 # Build a dictionary representing this resource record
            "name": name,                          # Store the owner name of the record
            "type": rtype,                         # Store the numeric type code
            "class": rclass,                       # Store the numeric class code
            "ttl": ttl,                            # Store the TTL value
            "rdlength": rdlength,                  # Store the RDATA length
            "rdata": rdata                         # Store the interpreted RDATA (IP string, NS name, or raw bytes)
        }
        records.append(record)                     # Append the parsed record to the list

    return records, offset                         # Return the list of records and the final offset


def parse_dns_response(message):                  # Define a function to parse an entire DNS response message
    header = struct.unpack(">HHHHHH", message[:12])  # Unpack the first 12 bytes as the DNS header
    transaction_id = header[0]                    # Extract the transaction ID from the header
    flags = header[1]                             # Extract the flags field from the header
    qdcount = header[2]                           # Extract the question count from the header
    ancount = header[3]                           # Extract the answer count from the header
    nscount = header[4]                           # Extract the authority count from the header
    arcount = header[5]                           # Extract the additional count from the header

    offset = 12                                   # Initialize the offset just after the header

    for _ in range(qdcount):                      # Loop over the number of questions in the message
        _, offset = parse_name(message, offset)   # Parse and ignore the question name
        offset += 4                               # Skip the QTYPE and QCLASS fields (2 bytes each)

    answers, offset = parse_resource_records(message, ancount, offset)   # Parse the answer section records
    authorities, offset = parse_resource_records(message, nscount, offset)  # Parse the authority section records
    additionals, offset = parse_resource_records(message, arcount, offset)  # Parse the additional section records

    parsed = {                                    # Build a dictionary representing the parsed DNS message
        "id": transaction_id,                     # Store the transaction ID
        "flags": flags,                           # Store the flags value
        "answers": answers,                       # Store the list of answer records
        "authorities": authorities,               # Store the list of authority records
        "additionals": additionals                # Store the list of additional records
    }

    return parsed                                 # Return the parsed DNS message components


def print_section(title, records):                # Define a helper function to print a section of resource records
    print(f"{title}")                             # Print the title line, for example "Answers section:"
    if not records:                               # Check if the list of records is empty
        print(" ")                                # Print a blank line if there are no records to display
        return                                    # Return early since there are no records

    for rr in records:                            # Loop over each resource record in the list
        if rr["type"] == 1:                       # If the record is an A record
            print(f" Name : {rr['name']} IP : {rr['rdata']}")  # Print the name and IPv4 address
        elif rr["type"] == 2:                     # If the record is an NS record
            print(f" Name : {rr['name']}  Name Server: {rr['rdata']}")  # Print the owner and name server domain
        else:                                     # For other types, provide a generic output
            print(f" Name : {rr['name']}  Type: {rr['type']}")          # Print the name and type code


def choose_next_server(parsed_response):          # Define a function that selects the next DNS server to query
    ns_names = [rr["rdata"] for rr in parsed_response["authorities"] if rr["type"] == 2]  # Collect all NS domain names
    additional_as = [rr for rr in parsed_response["additionals"] if rr["type"] == 1]      # Collect all A records from additional section

    for ns in ns_names:                           # Loop over each NS domain name
        for add in additional_as:                 # For each NS, loop over each additional A record
            if add["name"] == ns:                 # If the additional A record matches the NS domain name
                return add["rdata"]               # Return the corresponding IPv4 address as the next server IP

    if additional_as:                             # If no exact match is found but there is at least one A record
        return additional_as[0]["rdata"]          # Fallback to the first A record IP in the additional section

    return None                                   # If no suitable A record is found, return None to indicate failure


def extract_answer_ips(parsed_response):          # Define a function that extracts all IPv4 addresses from the answer section
    ips = []                                      # Initialize a list to collect IP addresses
    for rr in parsed_response["answers"]:         # Loop over each answer record
        if rr["type"] == 1:                       # Check if this answer is an A record
            ips.append(rr["rdata"])               # Append the IPv4 address string to the list
    return ips                                    # Return the list of collected IP addresses


def main():                                       # Define the main function that performs iterative DNS resolution
    if len(sys.argv) != 3:                        # Check that exactly two command-line arguments are provided
        print("Usage: python mydns.py <domain-name> <root-dns-ip>")  # Print a usage message for incorrect invocation
        sys.exit(1)                               # Exit the program with a non-zero status code

    domain_name = sys.argv[1]                     # Read the domain name to be resolved from the first argument
    current_server_ip = sys.argv[2]               # Read the IPv4 address of the root DNS server from the second argument

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket using IPv4
    udp_socket.settimeout(5.0)                   # Set a timeout of five seconds for socket operations

    while True:                                   # Begin the loop for iterative DNS resolution
        print("----------------------------------------------------------------")  # Print a separator line
        print(f"DNS server to query: {current_server_ip}")         # Show which DNS server is being queried now

        transaction_id, query = build_dns_query(domain_name)       # Build the DNS query for the target domain

        udp_socket.sendto(query, (current_server_ip, 53))          # Send the DNS query to port 53 of the current server

        try:                                                       # Begin a try block to catch timeout exceptions
            response_data, server_address = udp_socket.recvfrom(512)  # Receive up to 512 bytes from the server
        except socket.timeout:                                     # If the receive operation times out
            print("Reply timed out. Stopping resolution.")         # Inform that the reply timed out
            break                                                  # Exit the resolution loop

        parsed = parse_dns_response(response_data)                 # Parse the binary DNS response into structured data

        print("Reply received. Content overview:")                 # Indicate that a reply was received
        print(f" {len(parsed['answers'])} Answers.")               # Print the number of answer records
        print(f" {len(parsed['authorities'])} Intermediate Name Servers.")  # Print the number of NS records
        print(f" {len(parsed['additionals'])} Additional Information Records.")  # Print the number of additional records

        print_section("Answers section:", parsed["answers"])       # Print out the answer section in a readable format
        print_section("Authority Section:", parsed["authorities"]) # Print out the authority section records
        print_section("Additional Information Section:", parsed["additionals"])  # Print the additional information section

        answer_ips = extract_answer_ips(parsed)                     # Extract all IPv4 addresses from the answer section

        if answer_ips:                                              # Check if any A record answers were found
            # At this point the domain name has been resolved successfully
            # Answers are already printed above so we simply end the loop
            break                                                   # Break out of the iteration loop since resolution is complete

        next_server_ip = choose_next_server(parsed)                 # Choose the IP of the next intermediate DNS server to query

        if next_server_ip is None:                                  # If no next server could be determined
            print("No intermediate DNS server IP found. Stopping resolution.")  # Inform the user that resolution cannot continue
            break                                                   # Exit the loop because further progress is not possible

        current_server_ip = next_server_ip                          # Update the current server IP to the chosen intermediate server

    udp_socket.close()                                              # Close the UDP socket after completing the resolution process


if __name__ == "__main__":                                        # Check if this script is being run as the main program
    main()                                                         # Call the main function to start the DNS client
