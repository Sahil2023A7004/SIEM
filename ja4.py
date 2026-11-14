from scapy.all import sniff, IP, TCP, IPv6
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import hashlib
from capture import capture

# Session table: in memory dictionary to track active connections across both directions
# Allows ongoing encrypted packets to inherit the negotiated ja4 and domain name
session_table = {}

# Reassembly buffer: holds partial ClientHello bytes when TCP splits them across segments
hello_buffer = {}

# Table of sixteen reserved GREASE values defined by RFC 8701 that must be ignored
GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

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
    # If Scapy successfully parsed the TLS Client Hello, extract fingerprint using Scapy objects
    if not packet.haslayer(TLSClientHello):
        return None, None
    hello = packet[TLSClientHello]
    ciphers = hello.ciphers
    clean_ciphers = [c for c in ciphers if c not in GREASE_TABLE]
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
    return compute_ja4(clean_ciphers, clean_extensions, versions, sni, alpn, sni_hostname)

def try_get_hello_bytes(packet, session_key):
    # Checks raw TCP payload for a ClientHello start byte sequence
    # If the record is split across two TCP segments, buffers the first and
    # concatenates the second on arrival to produce the complete record
    if not packet.haslayer(TCP):
        return None
    payload = bytes(packet[TCP].payload)
    if len(payload) < 1:
        return None
    # Check if this is a continuation of a buffered partial ClientHello
    if session_key in hello_buffer:
        buf = hello_buffer[session_key]
        combined = buf["data"] + payload
        if len(combined) >= buf["needed"]:
            del hello_buffer[session_key]
            return bytes(combined[:buf["needed"]])
        else:
            buf["data"] = combined
            return None
    # Check if this starts a new TLS Handshake with ClientHello type
    # Byte 0 must be 0x16 (handshake) and byte 5 must be 0x01 (ClientHello)
    if len(payload) < 6:
        return None
    if payload[0] != 0x16 or payload[5] != 0x01:
        return None
    # Read the declared TLS record length from bytes 3 and 4
    record_len = int.from_bytes(payload[3:5], "big")
    needed = record_len + 5 # 5 bytes for TLS record header
    if len(payload) >= needed:
        return payload[:needed] # Complete in a single segment
    else:
        # Buffer partial record and wait for the next TCP segment
        hello_buffer[session_key] = {"data": bytearray(payload), "needed": needed}
        return None

def ja4_from_raw(data):
    # Parses a complete ClientHello from raw bytes when Scapy fails to dissect it
    # Returns the same (ja4_string, sni_hostname) pair as ja4()
    try:
        # TLS record header is 5 bytes, handshake header is 4 bytes, total offset 9
        pos = 9
        # Client version field (2 bytes) at the start of ClientHello body
        client_version = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        # Skip 32 byte random
        pos += 32
        # Session ID: 1 byte length then variable
        sid_len = data[pos]
        pos += 1 + sid_len
        # Cipher suites: 2 byte length then pairs of 2 byte values
        cs_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            c = int.from_bytes(data[pos + i:pos + i + 2], "big")
            ciphers.append(c)
        pos += cs_len
        # Compression methods: 1 byte length then variable
        cm_len = data[pos]
        pos += 1 + cm_len
        # Extensions block: 2 byte total length
        if pos + 2 > len(data):
            return None, None
        ext_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        ext_end = pos + ext_len
        ext_types = []
        sni_hostname = None
        alpn = "00"
        versions_found = []
        sig_algs = []
        # Walk each extension: 2 byte type, 2 byte length, then data
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            etype = int.from_bytes(data[pos:pos + 2], "big")
            elen = int.from_bytes(data[pos + 2:pos + 4], "big")
            edata = data[pos + 4:pos + 4 + elen]
            ext_types.append(etype)
            if etype == 0 and len(edata) >= 5:
                # SNI: skip list length (2) and type (1), read name length (2) then name
                name_len = int.from_bytes(edata[3:5], "big")
                sni_hostname = edata[5:5 + name_len].decode("utf-8", errors="ignore")
            elif etype == 16 and len(edata) >= 4:
                # ALPN: skip list length (2), read protocol length (1) then name
                proto_len = edata[2]
                proto = edata[3:3 + proto_len].decode("utf-8", errors="ignore")
                if proto:
                    alpn = proto[0] + proto[-1]
            elif etype == 43 and len(edata) >= 3:
                # Supported versions: 1 byte list length then 2 byte entries
                vlen = edata[0]
                for i in range(1, 1 + vlen, 2):
                    if i + 1 < len(edata):
                        v = int.from_bytes(edata[i:i + 2], "big")
                        versions_found.append(v)
            elif etype == 13 and len(edata) >= 4:
                # Signature algorithms: 2 byte list length then 2 byte entries
                alg_len = int.from_bytes(edata[0:2], "big")
                for i in range(2, 2 + alg_len, 2):
                    if i + 1 < len(edata):
                        a = int.from_bytes(edata[i:i + 2], "big")
                        sig_algs.append(a)
            pos += 4 + elen
        # Filter GREASE from ciphers and extensions
        clean_ciphers = [c for c in ciphers if c not in GREASE_TABLE]
        clean_extensions = [e for e in ext_types if e not in GREASE_TABLE]
        c_count = f"{min(len(clean_ciphers), 99):02d}"
        e_count = f"{min(len(clean_extensions), 99):02d}"
        sni = "d" if 0 in clean_extensions else "i"
        # Resolve TLS version from supported versions extension
        versions = "00"
        if 0x0304 in versions_found:
            versions = "13"
        elif 0x0303 in versions_found:
            versions = "12"
        if versions == "00" and client_version == 0x0303:
            versions = "12"
        return compute_ja4(clean_ciphers, clean_extensions, versions, sni, alpn, sni_hostname, sig_algs)
    except Exception:
        return None, None

def compute_ja4(clean_ciphers, clean_extensions, versions, sni, alpn, sni_hostname, sig_algs=None):
    # Shared computation that both ja4() and ja4_from_raw() use to produce the final hash
    c_count = f"{min(len(clean_ciphers), 99):02d}"
    e_count = f"{min(len(clean_extensions), 99):02d}"
    # 10 character ja4 prefix combining transport, version, sni, counts, and alpn
    prefix = f"t{versions}{sni}{c_count}{e_count}{alpn}"
    # Convert non GREASE ciphers to four digit hex, sort alphabetically, and hash with sha256
    hex_ciphers = sorted([f"{c:04x}" for c in clean_ciphers])
    cipher_string = ",".join(hex_ciphers)
    if clean_ciphers:
        cipher_hash = hashlib.sha256(cipher_string.encode()).hexdigest()[:12]
    else:
        cipher_hash = "000000000000"
    # Filter out SNI 0 and ALPN 16 from extension hash list per ja4 standard
    ext_for_hash = [e for e in clean_extensions if e not in (0, 16)]
    hex_ext = sorted([f"{e:04x}" for e in ext_for_hash])
    hex_string = ",".join(hex_ext)
    # Extract signature algorithms if not already provided
    if sig_algs is None:
        sig_algs = []
    hex_algorithms = "_".join([f"{a:04x}" for a in sig_algs])
    if sig_algs:
        raw = hex_string + "_" + hex_algorithms
    else:
        raw = hex_string
    if ext_for_hash:
        ext_hash = hashlib.sha256(raw.encode()).hexdigest()[:12]
    else:
        ext_hash = "000000000000"
    ja4_str = prefix + "_" + cipher_hash + "_" + ext_hash
    print(f"JA4 of Packet is: {ja4_str}")
    return ja4_str, sni_hostname

def process_packet(packet):
    # filter: drop packet if missing IP or TCP
    cap = capture(packet)
    if cap is None:
        return
    meta = metadata(packet)
    # Build bidirectional session key by sorting source and destination pairs
    endpoint_a = (meta["source_ip"], meta["source_port"])
    endpoint_b = (meta["dest_ip"], meta["dest_port"])
    session_key = tuple(sorted([endpoint_a, endpoint_b]))
    # First try: let Scapy parse the ClientHello directly
    ja4_data, sni_hostname = ja4(packet)
    # Second try: if Scapy could not parse it, check raw bytes and reassemble if split
    if ja4_data is None:
        raw = try_get_hello_bytes(packet, session_key)
        if raw is not None:
            ja4_data, sni_hostname = ja4_from_raw(raw)
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
