from scapy.all import sniff, IP, TCP, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import hashlib
from capture import capture

# Session table: in memory dictionary to track active connections across both directions
# Allows ongoing encrypted packets to inherit the negotiated ja4 and domain name
session_table = {}

def metadata(packet):
    # Extracts basic network layers and connection attributes from packet
    if packet.haslayer(IP):
        source_ip = packet["IP"].src
        destination_ip = packet["IP"].dst
        time_to_live = packet["IP"].ttl
    elif packet.haslayer(IPv6):
        source_ip = packet["IPv6"].src
        destination_ip = packet["IPv6"].dst
        time_to_live = packet["IPv6"].hlim # Hop limit acts as time to live for IPv6
    source_port = packet["TCP"].sport
    destination_port = packet["TCP"].dport
    flags = str(packet["TCP"].flags)
    packet_size = len(packet)
    master_directory = {
        "source_type": "network",
        "protocol": "tcp",
        "source_ip": source_ip,
        "dest_ip": destination_ip,
        "source_port": source_port,
        "dest_port": destination_port,
        "tcp_flags": flags,
        "packet_size": packet_size,
        "ja4": None,
        "event_type": "TCP",
        "metadata": {
            "time_to_live": time_to_live,
            "sni": None
        }
    }
    return master_directory

def ja4(packet):
    # Table of sixteen reserved GREASE values defined by RFC 8701 that must be ignored
    GREASE_TABLE = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 
        0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 
        0xcaca, 0xdada, 0xeaea, 0xfafa
    }
    # If packet does not contain a TLS Client Hello record, return empty pair
    if not packet.haslayer(TLSClientHello):
        return None, None
    else:
        hello = packet[TLSClientHello]
        ciphers = hello.ciphers
        clean_ciphers = []
        for c in ciphers:
            if c not in GREASE_TABLE:
                clean_ciphers.append(c)
            else:
                continue  
        clean_extensions = []
        extensions = hello.ext
        for e in extensions:
            if e.type not in GREASE_TABLE:
                clean_extensions.append(e.type)
        # Format counts to two digits with maximum cap of 99
        c_count = f"{min(len(clean_ciphers), 99):02d}"
        e_count = f"{min(len(clean_extensions), 99):02d}"
        sni = "i"
        sni_hostname = None
        versions = "00"
        alpn = "00"
        for e in extensions:
            if e.type == 0:
                sni = "d" # Indicates destination domain was supplied in extension
                if hasattr(e, "servernames") and len(e.servernames) > 0:
                    sni_hostname = e.servernames[0].servername.decode("utf-8", errors="ignore")
            if e.type == 16:
                # ALPN: extract first and last character of negotiated application protocol
                if hasattr(e, "protocols") and len(e.protocols) > 0:
                    raw_protocol = e.protocols[0].protocol.decode("utf-8", errors="ignore")
                    alpn = raw_protocol[0] + raw_protocol[-1]
            if e.type == 43 and hasattr(e, "versions"):
                # Supported versions extension overrides outer header version
                if 0x0304 in e.versions:
                    versions = "13"
                elif 0x0303 in e.versions:
                    versions = "12"
        if versions == "00":
            if hello.version == 0x0303:
                versions = "12"
        # 10 character ja4 prefix combining transport, version, sni, counts, and alpn
        prefix = f"t{versions}{sni}{c_count}{e_count}{alpn}"
        # Convert non GREASE ciphers to four digit hex, sort alphabetically, and hash with sha256
        hex_ciphers = [f"{c:04x}" for c in clean_ciphers]
        sorted_ciphers = sorted(hex_ciphers)
        cipher_string = ",".join(sorted_ciphers)
        if clean_ciphers:
            cipher_hash = hashlib.sha256(cipher_string.encode()).hexdigest()[:12]
        else:
            cipher_hash = "000000000000"
        # Filter out SNI 0 and ALPN 16 from extension hash list per ja4 standard
        extension_for_hash = []
        for id in clean_extensions:
            if id not in (0, 16):
                extension_for_hash.append(id)
        hex_extensions = [f"{id:04x}" for id in extension_for_hash]
        sorted_extensions = sorted(hex_extensions)
        hex_string = ",".join(sorted_extensions)
        # Extract signature algorithms from extension 13 if present
        signature_algorithms = []
        for e in hello.ext:
            if e.type == 13 and hasattr(e, "sig_algs"):
                signature_algorithms = e.sig_algs
        hex_algorithms = [f"{algo:04x}" for algo in signature_algorithms]
        hex_algorithms = "_".join(hex_algorithms)
        if signature_algorithms:
            raw = hex_string + "_" + hex_algorithms
        else:
            raw = hex_string
        if extension_for_hash:
            ext_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]
        else:
            ext_hash = "000000000000"
        ja4 = prefix + "_" + cipher_hash + "_" + ext_hash
        print(f"JA4 of Packet is: {ja4}")       
        return ja4, sni_hostname

def process_packet(packet):
    # Station 1 gatekeeper filter: drop packet if missing IP or TCP
    cap = capture(packet)
    if cap is None:
        return          
    meta = metadata(packet)
    # Build bidirectional session key by sorting source and destination pairs
    endpoint_a = (meta["source_ip"], meta["source_port"])
    endpoint_b = (meta["dest_ip"], meta["dest_port"])
    session_key = tuple(sorted([endpoint_a, endpoint_b]))
    # Compute ja4 and extract destination hostname from Client Hello
    ja4_data, sni_hostname = ja4(packet)
    if ja4_data is not None:
        # Save fresh handshake details into session table in memory
        session_table[session_key] = (ja4_data, sni_hostname)
        meta["ja4"] = ja4_data
        meta["metadata"]["sni"] = sni_hostname
    else:
        # Subsequent encrypted packets look up previously stored fingerprint from session table
        cached = session_table.get(session_key)
        if cached:
            meta["ja4"] = cached[0]
            meta["metadata"]["sni"] = cached[1]
    print(meta)
    return meta

if __name__ == "__main__":
    # Start live packet sniffing on eth0 for TLS traffic on port 443
    sniff(iface="eth0", filter="tcp port 443", prn=process_packet, store=0)
