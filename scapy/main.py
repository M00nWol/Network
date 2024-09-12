from scapy.all import sniff, wrpcap

# list to save packets
packets = []

# append packet to list
def packet_callback(packet):
    packets.append(packet)
    print(packet.summary)

# capture packet
sniff(filter="tcp",prn=packet_callback, count=10)

# save packets as pcap file
wrpcap("./captured_packets.pcap", packets)