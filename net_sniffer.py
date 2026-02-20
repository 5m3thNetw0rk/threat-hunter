from scapy.all import sniff, IP, TCP, Raw

def process_packet(packet):
    # Check if the packet has an IP layer and a TCP layer
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Look for common insecure ports (80=HTTP, 21=FTP, 23=Telnet)
        insecure_ports = [80, 21, 23]
        
        if packet[TCP].dport in insecure_ports or packet[TCP].sport in insecure_ports:
            print(f"\n[!] INSECURE PROTOCOL DETECTED: {ip_src} -> {ip_dst}")
            
            # If the packet has a 'Raw' load (the actual data), check for keywords
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Search for sensitive keywords in the cleartext data
                keywords = ["user", "pass", "login", "password"]
                if any(key in payload.lower() for key in keywords):
                    print(f"    [🚨] POTENTIAL CREDENTIALS FOUND: {payload.strip()[:100]}")

print("[*] Network Sniffer Started... Press Ctrl+C to stop.")
# 'sniff' listens to the network. 'store=0' saves memory by not keeping packets in RAM.
sniff(filter="tcp", prn=process_packet, store=0)
