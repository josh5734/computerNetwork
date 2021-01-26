import pcapy
from struct import *
import socket

# Interface: Selection of Networks
devs = pcapy.findalldevs()
for i, d in enumerate(devs):
    print(str(i+1) + ". " + d)
dev = int(input("which one do you want to sniff? 1~{} : ".format(len(devs))))-1
dev = devs[dev]

# Interface: To choose whether to sniff DNS or HTTP
apps = ['HTTP', 'DNS']
for i, a in enumerate(apps):
    print(str(i+1) + ". " + a)
app = int(input("Select HTTP Or DNS: 1~{} : ".format(2)))-1
app = apps[app]
cap = pcapy.open_live(dev, 65536, 1, 0)
if (app == "HTTP"):
    cap.setfilter("port 80")
elif(app == "DNS"):
    cap.setfilter("port 53")

print()


def ip_header_analysis(packet):
    # IP 헤더의 정보를 분석하는 Method
    # Ethernet 헤더의 길이 : 14 -> IP 헤더는 Packet[14:34]로 Base 분석을 함 / 아래 정보는 20Bytes 내에 존재
    iphdr = unpack("!BBHHHBBH4s4s", packet[14:34])
    data = {
        "ip_header_raw": iphdr,  # 전체 IP 헤더 정보
        "ip_version": packet[14] >> 4,  # IP Version 정보
        "ip_header_len": (packet[14] & 0xF) * 4,  # IP header의 길이
        "source_ip_addr": socket.inet_ntoa(iphdr[8]),  # Source_IP_address
        # Destination_IP_address
        "destination_ip_addr": socket.inet_ntoa(iphdr[9]),
        "ip_protocol": iphdr[6]  # IP Protocol 정보 -> TCP / UDP 판별할 용도
    }

    return data

# start_idx를 parameter로 입력하여 IP Header의 길이를 반영해서 TCP Header의 시작위치 형성


def tcp_header_analysis(packet, start_idx):

    # TCP 헤더의 길이는 Basic 20Bytes이고, 이 안에서 아래의 data 정보를 찾을 수 있음
    tcp_header = packet[start_idx:start_idx+20]
    tcp_header = unpack("!HHLLBBHHH", tcp_header)  # 쪼개기

    data = {
        "source_port": tcp_header[0],  # TCP Header의 Source_port
        "destination_port": tcp_header[1],  # TCP Header의 Destination_port
        # TCP Header의 길이를 알려준다 -> HTTP, DNS의 Header 시작점을 변경시킴
        "tcp_header_length": (tcp_header[4] >> 4) * 4,
    }
    return data

# start_idx를 parameter로 입력하여 IP Header의 길이를 반영해서 UDP Header의 시작위치 형성


def udp_header_analysis(packet, start_idx):

    udp_header = packet[start_idx:start_idx+8]  # UDP 헤더는 8바이트
    udp_header = unpack("!HHHH", udp_header)

    data = {
        "source_port": udp_header[0],  # TCP Header의 Source_port
        "destination_port": udp_header[1],  # TCP Header의 Destination_port
        "udp_header_length": udp_header[2]
    }

    return data


cnt = 1
while(True):
    (header, packet) = cap.next()

    # IP, UDP, TCP의 정보를 Return해서 받아온다.
    ip_info = ip_header_analysis(packet)
    udp_info = udp_header_analysis(packet, 14+ip_info["ip_header_len"])
    tcp_info = tcp_header_analysis(packet, 14+ip_info["ip_header_len"])
    cnt += 1

    # HTTP 헤더 분석
    if(app == "HTTP"):
        if(ip_info["ip_protocol"] == 6):  # TCP
            header_length = sum(
                [ip_info["ip_header_len"], tcp_info["tcp_header_length"], 14]
            )
            # Decoding
            http_before = packet[header_length:]
            http_after = http_before.decode("iso-8859-1")

            # Request
            if(('HTTP' in http_after) and ('User-Agent' in http_after)):
                print(str(cnt) + " " + ip_info.get("source_ip_addr")+": " + str(tcp_info.get("source_port")),
                      ip_info.get("destination_ip_addr")+": " + str(tcp_info.get("destination_port")) + " HTTP Requset")
                print(http_after)

            # Response
            if(('HTTP' in http_after) and ('Content' in http_after)):
                print(str(cnt) + " " + ip_info.get("source_ip_addr")+": " + str(tcp_info.get("source_port")),
                      ip_info.get("destination_ip_addr")+": " + str(tcp_info.get("destination_port")) + " HTTP Response")
                http_after = http_after.split('\r\n\r\n')[0]
                print(http_after)

        elif(ip_info["ip_protocol"] == 17):  # UDP
            header_length = sum(
                # UDP Header length =12, Ethernet Header Length = 14Bytes
                [ip_info["ip_header_len"], 22]
            )
            # Decoding
            http_before = packet[header_length:]
            http_after = http_before.decode("iso-8859-1")

            # Request
            if(('HTTP' in http_after) and ('Host' in http_after)):
                print(str(cnt) + " " + ip_info.get("source_ip_addr")+": " + str(udp_info.get("source_port")),
                      ip_info.get("destination_ip_addr")+": " + str(udp_info.get("destination_port")) + " DNS ID : ")
                print(http_after)

            # Response
            elif(('HTTP' in http_after) and ('Content' in http_after)):
                print(str(cnt) + " " + ip_info.get("source_ip_addr")+": " + str(udp_info.get("source_port")),
                      ip_info.get("destination_ip_addr")+": " + str(udp_info.get("destination_port")) + " HTTP Response")
                http_after = http_after.split('\r\n\r\n')[0]
                print(http_after)

    # DNS 헤더를 분석
    elif(app == 'DNS'):
        if(ip_info["ip_protocol"] == 6):  # TCP
            header_length = sum(
                [ip_info["ip_header_len"], tcp_info["tcp_header_length"], 14]
            )
            # DNS 헤더의 길이는 12Bytes
            dns_header = packet[header_length:header_length+12]

            dns_id = dns_header[:2].hex()  # DNS ID
            # DNS 헤더의 Flag 부분을 Bytes -> Bit로 나눈다.
            dns_flag = bin(int(dns_header[2:4].hex())).lstrip('0b').zfill(16)

            # DNS flag Part / 위에서 Bit 단위로 쪼갠 dns_flag 정보를 이용하여, Index로 각 비트를 접근
            dns_QR = dns_flag[0]
            dns_Opcode = dns_flag[1:5]
            dns_AA = dns_flag[5]
            dns_TC = dns_flag[6]
            dns_RD = dns_flag[7]
            dns_RA = dns_flag[8]
            dns_Z = dns_flag[9:12]
            dns_RCODE = dns_flag[12:16]

            dns_QD = dns_header[4:6].hex()[-1]
            dns_AN = dns_header[6:8].hex()[-1]
            dns_NS = dns_header[8:10].hex()[-1]
            dns_AR = dns_header[10:12].hex()[-1]

            # 출력
            print(str(cnt) + " " + ip_info.get("source_ip_addr")+":" + str(udp_info.get("source_port")),
                  ip_info.get("destination_ip_addr")+":" + str(udp_info.get("destination_port")) + " DNS ID:" + dns_id)
            print(dns_QR + ' | ' + dns_Opcode + ' | ' + dns_AA + ' | ' + dns_TC +
                  ' | ' + dns_RD + ' | ' + dns_RA + ' | ' + dns_Z + ' | ' + dns_RCODE)
            print("QDCOUNT : " + dns_QD)
            print("ANCOUNT : " + dns_AN)
            print("NSCOUNT : " + dns_NS)
            print("AROUNT : " + dns_AR)
            print()

        elif(ip_info["ip_protocol"] == 17):  # UDP

            # UDP 에서 UDP Header 길이 = 8Bytes, Ethernet Header 길이 = 14 Bytes -> 22Bytes
            header_length = sum(
                [ip_info["ip_header_len"], 22]
            )
            dns_header = packet[header_length:header_length+12]
            dns_id = dns_header[:2].hex()

            dns_flag = bin(int(dns_header[2:4].hex())).lstrip('0b').zfill(16)
            dns_QR = dns_flag[0]
            dns_Opcode = dns_flag[1:5]
            dns_AA = dns_flag[5]
            dns_TC = dns_flag[6]
            dns_RD = dns_flag[7]
            dns_RA = dns_flag[8]
            dns_Z = dns_flag[9:12]
            dns_RCODE = dns_flag[12:16]

            dns_QD = dns_header[4:6].hex()[-1]
            dns_AN = dns_header[6:8].hex()[-1]
            dns_NS = dns_header[8:10].hex()[-1]
            dns_AR = dns_header[10:12].hex()[-1]

            # 출력
            print(str(cnt) + " " + ip_info.get("source_ip_addr")+":" + str(udp_info.get("source_port")),
                  ip_info.get("destination_ip_addr")+":" + str(udp_info.get("destination_port")) + " DNS ID:" + dns_id)
            print(dns_QR + ' | ' + dns_Opcode + ' | ' + dns_AA + ' | ' + dns_TC +
                  ' | ' + dns_RD + ' | ' + dns_RA + ' | ' + dns_Z + ' | ' + dns_RCODE)
            print("QDCOUNT : " + dns_QD)
            print("ANCOUNT : " + dns_AN)
            print("NSCOUNT : " + dns_NS)
            print("AROUNT : " + dns_AR)
            print()
