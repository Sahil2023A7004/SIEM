
from scapy.all import sniff, IP, IPv6, TCP
from uuid import uuid4

import ja4
from database import store_ja4_event, close_database


# Tracks active TCP connections
active_sessions = {}

# Tracks connections whose JA4 has already been stored
stored_sessions = set()


def get_session_key(packet):
    """Create a bidirectional TCP connection key."""

    if not packet.haslayer(TCP):
        return None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return None

    src = (src_ip, packet[TCP].sport)
    dst = (dst_ip, packet[TCP].dport)

    return tuple(sorted([src, dst]))


def clear_session(session_key):
    """Remove all tracking data for a connection."""

    active_sessions.pop(session_key, None)
    stored_sessions.discard(session_key)

    ja4.session_table.pop(session_key, None)
    ja4.hello_buffer.pop(session_key, None)


def handle_packet(packet):

    session_key = get_session_key(packet)

    if session_key is None:
        return

    flags = int(packet[TCP].flags)

    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    fin = bool(flags & 0x01)
    rst = bool(flags & 0x04)

    # Detect a new TCP connection.
    # A repeated SYN with the same sequence number is a retransmission.
    if syn and not ack:

        syn_seq = int(packet[TCP].seq)
        existing = active_sessions.get(session_key)

        if existing is None or existing["syn_seq"] != syn_seq:

            clear_session(session_key)

            active_sessions[session_key] = {
                "connection_id": str(uuid4()),
                "syn_seq": syn_seq
            }

    # Support connections first observed after their SYN packet.
    if session_key not in active_sessions:

        active_sessions[session_key] = {
            "connection_id": str(uuid4()),
            "syn_seq": None
        }

    try:

        # Run the existing JA4 fingerprinting engine
        event = ja4.process_packet(packet)

        if event is None:
            return

        # Store only the first JA4 observation per connection
        if event.get("ja4") and session_key not in stored_sessions:

            event["event_type"] = "TLS_CLIENT_HELLO"

            event["connection_id"] = (
                active_sessions[session_key]["connection_id"]
            )

            store_ja4_event(event)

            stored_sessions.add(session_key)

            print(
                "\n[DATABASE] JA4 event stored:",
                event["ja4"]
            )

    finally:

        # Clean up when a connection closes or resets
        if fin or rst:
            clear_session(session_key)


if __name__ == "__main__":

    print("Starting JA4 network collector...")
    print("Interface: en0")
    print("Monitoring: TCP port 443")
    print("Duplicate prevention: enabled")
    print("Press CTRL+C to stop.")

    try:

        sniff(
            iface="en0",
            filter="tcp port 443",
            prn=handle_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nCollector stopped.")

    finally:
        close_database()
        print("Database connection closed.")

