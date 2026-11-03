from scapy.all import sniff, IP, TCP, IPv6

def capture(packet):#Packet capture function
    if not ((packet.haslayer(IP) or packet.haslayer(IPv6)) and packet.haslayer(TCP)):#Check for IP and TCP
        return None#If absent abort program.
    return packet#If present return the packet to RAM. 
if __name__ == "__main__":
    sniff(iface="any", filter="tcp port 443 or tcp port 80", prn=capture, store=0)
# Sniff is an inbuilt function that works with NIC to capture packets, 
# iface the interface we are using
# filter is we are capturing trffic on tcp port 443 and 80 only i.e HTTP & HTTPS No UDP 
# prn is an inbuilt module that repeatedly calls our function that is capture
# store is a function if we want to store the captured packets in a file 0 means FALSE

#Variables Used: packet to store incoming packet and return filtered packet.
#If you want to interact with this packet data you have to use variable name "packet" 
#Working prn inside calls the capture, sniff gets packet from NIC
#Supplies to capture where it is examined by hasLayer for IP and TCP
#If both IP and TCP exist Packet is passed to next file for JA4 fingerinting 
#OR if either IP or TCP or both are missing packet is dropped