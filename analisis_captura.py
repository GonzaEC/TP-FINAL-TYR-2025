from scapy.all import rdpcap
from collections import Counter

# Ruta a tu archivo .cap o .pcapng
packets = rdpcap("captura_tpfinal.cap")

# Contador de protocolos
protocol_counter = Counter()

# Recorremos los paquetes
for pkt in packets:
    if pkt.haslayer("ARP"):
        protocol_counter["ARP"] += 1
    elif pkt.haslayer("ICMP"):
        protocol_counter["ICMP"] += 1
    elif pkt.haslayer("DNS"):
        protocol_counter["DNS"] += 1
    elif pkt.haslayer("TCP"):
        if pkt.haslayer("HTTP"):
            protocol_counter["HTTP"] += 1
        else:
            protocol_counter["TCP"] += 1
    elif pkt.haslayer("UDP"):
        protocol_counter["UDP"] += 1
    elif pkt.haslayer("IP"):
        protocol_counter["IPv4"] += 1
    else:
        protocol_counter["Otros"] += 1

# Total
total = sum(protocol_counter.values())

# Imprimir resultados
print("PROTOCOLO\tCANTIDAD\tPORCENTAJE")
for proto, count in protocol_counter.items():
    porcentaje = (count / total) * 100
    print(f"{proto}\t\t{count}\t\t{porcentaje:.2f}%")
