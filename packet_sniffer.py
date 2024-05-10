from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Packet handler function to process each captured packet
def packet_handler(packet):
    # Packet Headers
    print("Packet Headers:")
    print(f"Source IP: {packet[IP].src}")
    print(f"Destination IP: {packet[IP].dst}")
    if packet.haslayer(TCP):
        print(f"Protocol: TCP")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"Protocol: UDP")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    elif packet.haslayer(ICMP):
        print(f"Protocol: ICMP")

    # Packet Payloads
    if packet.haslayer(Raw):
        print("Packet Payloads:")
        print(packet[Raw].load)

# Sniffing network traffic
sniff(prn=packet_handler, count=100)  
