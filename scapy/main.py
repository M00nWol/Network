from scapy.all import sniff, wrpcap

# list to save packets
packets = []

# count number of packet per protocol
tcp_count = 0
udp_count = 0
icmp_count = 0

# handle packets
def packet_callback(packet):
    global tcp_count, udp_count, icmp_count

    # save packets to list
    packets.append(packet)
    print(packet.summary)

    # increase count per protocol
    if packet.haslayer("TCP"):
        tcp_count += 1
    elif packet.haslayer("UDP"):
        udp_count += 1
    elif packet.haslayer("ICMP"):
        icmp_count += 1

    # real-time statistics output
    print(f"TCP: {tcp_count}. UDP: {udp_count}, ICMP: {icmp_count}")
    print("-" * 50)


# capture packet
sniff(prn=packet_callback, count=50)

# save packets as pcap file
wrpcap("./captured_packets.pcap", packets)