from scapy.all import sniff

# packer capture
def packet_callback(packet):
    print(packet.summary())

# capture packet in network interface
sniff(prn=packet_callback, count=10)