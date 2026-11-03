from scapy.all import sniff, IP, TCP
from scapy.layers.tls.handshake import TLSClientHello
import hashlib
from capture import capture
session_table = {}

def metadata(packet):
        source_ip = packet["IP"].src
        destination_ip = packet["IP"].dst
        time_to_live = packet["IP"].ttl
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
                "metadata":{
                "time_to_live": time_to_live,
                "sni": None
                }
                }
        return master_directory
def ja4(packet):
        GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 
    0xcaca, 0xdada, 0xeaea, 0xfafa
}
        if not packet.haslayer(TLSClientHello):
                return None
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
        c_count = f"{min(len(clean_ciphers), 99):02d}"
        e_count = f"{min(len(clean_extensions), 99):02d}"
        sni = "i"
        sni_hostname = None
        versions = "00"
        alpn = "00"
        for e in extensions:
            if e.type == 0:
                sni = "d"
                if hasattr(e, "servernames") and len(e.servernames) > 0:
                    sni_hostname = e.servernames[0].servername.decode("utf-8", errors="ignore")
            if e.type == 16:
                if hasattr(e, "protocols") and len(e.protocols) > 0:
                    raw_protocol = e.protocols[0].protocol.decode("utf-8", errors="ignore")
                    alpn = raw_protocol[0] + raw_protocol[-1]
            if e.type == 43 and hasattr(e, "versions"):
                if 0x0304 in e.versions:
                 versions = "13"
                elif 0x0303 in e.versions:
                 versions = "12"
        if versions == "00":
            if hello.version == 0x0303:
                versions = "12"
        prefix = f"t{versions}{sni}{c_count}{e_count}{alpn}"
        hex_ciphers = [f"{c:04x}" for c in clean_ciphers]
        sorted_ciphers = sorted(hex_ciphers)
        cipher_string = ",".join(sorted_ciphers)
        if clean_ciphers:
         cipher_hash = hashlib.sha256(cipher_string.encode()).hexdigest()[:12]
        else:
            cipher_hash = "000000000000"
        extension_for_hash = []
        for id in clean_extensions:
            if id not in (0,16):
                extension_for_hash.append(id)
        hex_extensions = [f"{id:04x}" for id in extension_for_hash]
        sorted_extensions = sorted(hex_extensions)
        hex_string = ",".join(sorted_extensions)
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
        return ja4
def process_packet(packet):
    cap = capture(packet)
    if cap is None:
        return          
    meta = metadata(packet)
    ja4_data = ja4(packet)
    meta["ja4"] = ja4_data
    endpoint_a = (meta["source_ip"], meta["source_port"])
    endpoint_b = (meta["dest_ip"], meta["dest_port"])
    session_key = tuple(sorted([endpoint_a, endpoint_b]))
    return meta

sniff(iface="WiFi", filter="tcp port 443", prn=process_packet, store=0)
