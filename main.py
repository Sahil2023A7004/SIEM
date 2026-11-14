from scapy.all import sniff
from ja4 import process_packet
from shipper import start_shipper, enqueue_log

def on_packet(packet):
    meta = process_packet(packet)
    if meta:
        enqueue_log(meta)

if __name__ == "__main__":
    print("[INFO] Starting SIEM Network Sensing Layer...")
    start_shipper()
    try:
        sniff(iface="eth0", filter="tcp port 443", prn=on_packet, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Sensor stopped by user.")
