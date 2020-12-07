import socket
from scapy.all import *


def get_socket(sock_proto):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	return s


def get_icmp_ip(ttl, dst_ip, time_to_abort):
	icmp_id = random.randint(1000, 2000)
	seq = random.randint(1000, 2000)
	icmp = ICMP(seq=seq, id=icmp_id)
	packet = IP(dst=dst_ip, ttl=ttl)/icmp
	
	with get_socket(socket.IPPROTO_ICMP) as s_send:
		result = []
		th = threading.Thread(target=get_icmp_node_ip, args=(s_send, icmp_id, seq, dst_ip, result))
		th.daemon = True
		s_send.sendto(raw(packet), (dst_ip, 0))
		s_send.sendto(raw(packet), (dst_ip, 0))
		s_send.sendto(raw(packet), (dst_ip, 0))
		th.start()	
		th.join(time_to_abort)


		if result:
			return result[0]
		else:
			return None


def get_icmp_node_ip(recv_sock, icmp_id, seq, dst_ip, result):
	start_time = time.monotonic()
	try:
		while True:
			data = recv_sock.recvfrom(1024)
			ip_data = IP(data[0])
			
			if is_icmp_matches(ip_data, icmp_id, seq, dst_ip):
				result.append((ip_data.src, time.monotonic() - start_time))
				return
	except:
		return


def is_icmp_matches(recvd_ip_data, icmp_id, seq, dst_ip):
	icmp_data = recvd_ip_data[ICMP]
	if (icmp_data.seq == seq and 
		icmp_data.id == icmp_id and
		recvd_ip_data.src == dst_ip):
		return True

	recvd_ip_data = icmp_data.payload.payload

	return (recvd_ip_data.seq == seq and 
		recvd_ip_data.id == icmp_id)