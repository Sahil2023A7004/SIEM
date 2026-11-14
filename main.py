from scapy.all import sniff
from ja4 import process_packet
from shipper import start_shipper, enqueue_log

def on_packet(packet):
    meta = process_packet(packet)
    if meta:
        enqueue_log(meta)
        