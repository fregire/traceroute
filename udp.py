import socket
from scapy.all import *
from funcs import get_socket


def get_udp_ip(ttl, dst_ip, dst_port, time_to_abort):
	seq = random.randint(1000, 2000)
	sport = random.randint(50000, 53000)
	udp_pack = UDP(dport=dst_port, sport=sport)/"@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
	ip_pack = IP(dst=dst_ip, ttl=ttl)
	packet = ip_pack/udp_pack
	icmp_sock = get_socket(socket.IPPROTO_ICMP)
	udp_sock = get_socket(socket.IPPROTO_UDP)

	with udp_sock:
		with icmp_sock:

			result = []
			th = threading.Thread(
				target=get_node_ip, 
				args=(icmp_sock, udp_pack, dst_ip, result))
			th.daemon = True
			udp_sock.sendto(raw(packet), (dst_ip, dst_port))
			udp_sock.sendto(raw(packet), (dst_ip, dst_port))
			udp_sock.sendto(raw(packet), (dst_ip, dst_port))
			th.start()	
			th.join(time_to_abort)


			if result:
				return result[0]
			else:
				return None


def get_node_ip(icmp_sock, udp_pack, dst_ip, result):
	start_time = time.monotonic()
	try:
		while True:
			data = icmp_sock.recvfrom(1024)
			ip_data = IP(data[0])

			icmp_data = ip_data[ICMP]
			if icmp_data.payload.dst == dst_ip:
				udp_data = icmp_data.payload.payload
				if (udp_data.dport == udp_pack.dport and
					udp_data.sport == udp_pack.sport):
					result.append((ip_data.src, time.monotonic() - start_time))
					return

	except Exception as e:
		return
