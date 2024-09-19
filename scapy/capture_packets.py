# capture_packets.py
from scapy.all import sniff, wrpcap
from scapy.layers.inet import *



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

    if packet.haslayer(IP):
        # IP 정보 얻어오기
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_length = len(packet)

        # 포트 번호 초기화
        src_port = None
        dst_port = None

        # 패킷이 TCP/UDP 층인지 체크하고 포트 정보 뽑아내기
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_count += 1
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            udp_count += 1
        elif packet.haslayer(ICMP):
            icmp_count += 1

        # 패킷 정보 뽑아내기
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        if src_port and dst_port:
            print(f"Source Port: {src_port}, Destination Port: {dst_port}")
        print(f"Packet Length: {packet_length} bytes")
        print(packet.summary())
        print(f"TCP: {tcp_count}, UDP: {udp_count}, ICMP: {icmp_count}")
        print("-"*50)

# capture packet
# GUI 사용 안 할 때를 대비해 count와 filter 설정한 것
# => GUI 코드와 독립적으로 실행 가능
def start_capture(count=10, filter="tcp"):
    sniff(filter=filter,prn=packet_callback, count=count)

    # save packets as pcap file
    wrpcap("./captured_packets.pcap", packets)

if __name__ == "__main__":
    start_capture(count=10, filter="tcp or udp or icmp")