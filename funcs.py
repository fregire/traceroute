import socket


def get_socket(sock_proto):
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	return s