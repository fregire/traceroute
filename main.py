from scapy.all import *
import socket
import argparse
import time
import threading


def get_socket(sock_proto):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	return s

def get_node_ip(recv_sock, response_packet, result):
	start_time = time.monotonic()

	while True:
		data = recv_sock.recvfrom(1024)
		ip = IP(data[0])
		ip_packet = raw(ip)

		if response_packet in ip_packet:
			result.append((ip[IP].src, time.monotonic() - start_time))
			return


def get_router_ip(ttl, scapy_proto, sock_proto, dst_ip, time_to_abort, dst_port=0):
	response_packet = raw(IP(dst=dst_ip, ttl=1)/scapy_proto)

	packet = IP(dst=dst_ip, ttl=ttl)/scapy_proto
	s_send = get_socket(sock_proto)
	s_recv = get_socket(socket.IPPROTO_ICMP)
	s_send.sendto(raw(packet), (dst_ip, dst_port))
	result = []
	th = threading.Thread(target=get_node_ip, args=(s_recv, response_packet, result))
	th.start()
	th.join(time_to_abort)

	if result:
		return result[0]
	else:
		return None


def parse_args():
	parser = argparse.ArgumentParser(description='Traceroute')
	parser.add_argument('ip', help='Destination ip')
	parser.add_argument('proto', help='Protocol to send packets: udp, tcp, icmp')
	parser.add_argument('-p', '--port', help='Destination port for TCP and UDP', default=0, type=int)

	return parser.parse_args()


SCAPY_PROTOS = {
	'udp': UDP(),
	'tcp': TCP(),
	'icmp': ICMP()
}

SOCKET_PROTOS = {
	'udp': socket.IPPROTO_UDP,
	'tcp': socket.IPPROTO_TCP,
	'icmp': socket.IPPROTO_ICMP
}


def main():
	args = parse_args()
	ttl = 1

	while True:
		result = get_router_ip(
			ttl, 
			SCAPY_PROTOS[args.proto], 
			SOCKET_PROTOS[args.proto], 
			args.ip, 
			2,
			args.port)
		if result:
			ip, time_in_s = result
			print(ip, time_in_s)
		else:
			print("*****")

		ttl += 1
		


if __name__ == "__main__":
	main()