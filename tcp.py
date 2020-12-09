import socket
from scapy.all import *
from funcs import get_socket


def get_tcp_ip(ttl, dst_ip, dst_port, time_to_abort):
	seq = random.randint(1000, 2000)
	sport = random.randint(50000, 53000)
	tcp_pack = TCP(seq=seq, dport=dst_port, sport=sport)
	tcp_closed = TCP(seq=seq, dport=dst_port, sport=sport, flags=4)
	ip_pack = IP(dst=dst_ip, ttl=ttl)
	packet = ip_pack/tcp_pack
	packet_closed = ip_pack/tcp_closed
	icmp_sock = get_socket(socket.IPPROTO_ICMP)
	tcp_sock = get_socket(socket.IPPROTO_TCP)

	with tcp_sock:
		with icmp_sock:

			result = []
			th = threading.Thread(
				target=get_node_ip, 
				args=(icmp_sock, tcp_sock, tcp_pack, dst_ip, dst_port, result))
			th.daemon = True
			tcp_sock.sendto(raw(packet), (dst_ip, dst_port))
			th.start()	
			th.join(time_to_abort)
			tcp_sock.sendto(raw(packet_closed), (dst_ip, dst_port))


			if result:
				return result[0]
			else:
				return None


def get_node_ip(icmp_sock, tcp_sock, tcp_pack, dst_ip, dst_port, result):
	ack = tcp_pack.seq + 1

	start_time = time.monotonic()
	try:
		while True:
			readers, _, _ = select.select([icmp_sock, tcp_sock], [], [])

			for reader in readers:
				data = reader.recvfrom(1024)
				ip_data = IP(data[0])

				if reader is icmp_sock:
					icmp_data = ip_data[ICMP]
					if icmp_data.payload.dst == dst_ip:
						tcp_data = icmp_data.payload.payload
						if (tcp_data.seq == tcp_pack.seq and
							tcp_data.dport == tcp_pack.dport and
							tcp_data.sport == tcp_pack.sport):
							result.append((ip_data.src, time.monotonic() - start_time))
							return

				if reader is tcp_sock:
					recvd_tcp = ip_data[TCP]
					if (recvd_tcp.dport == tcp_pack.sport and
						recvd_tcp.sport == tcp_pack.dport and
						recvd_tcp.ack == ack):
						result.append((ip_data.src, time.monotonic() - start_time))
						return

	except:
		return
