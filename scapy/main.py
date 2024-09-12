from scapy.all import sniff

# packer capture and show details
def packet_callback(packet):
    if packet.haslayer("IP"):
        print(f"Source IP: {packet['IP'].src}")
        print(f"Destination IP: {packet['IP'].dst}")
        print(f"Protocol: {packet['IP'].proto}")
        print("-" * 50)

# capture packet in network interface
# filer : TCP
sniff(filter="tcp",prn=packet_callback, count=10)