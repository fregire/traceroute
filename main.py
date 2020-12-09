from scapy.all import *
import socket
import argparse
import time
import threading
import random
from icmp import get_icmp_ip
from tcp import get_tcp_ip
from udp import get_udp_ip

def parse_args():
	parser = argparse.ArgumentParser(description='Traceroute')
	parser.add_argument('ip', help='Destination ip')
	parser.add_argument('proto', help='Protocol to send packets: udp, tcp, icmp')
	parser.add_argument('-p', '--port', help='Destination port for TCP and UDP', default=0, type=int)

	return parser.parse_args()


def main():
	args = parse_args()
	ttl = 1
	num = 1

	#result = get_udp_ip(8, args.ip, args.port, 2)

	#print(result)

	while True:
		result = get_udp_ip(ttl, args.ip, args.port, 2)
		
		if result:
			ip, time = result
			print(num, ip, time)

			if ip == args.ip:
				break
		else:
			print(num, "*")

		num += 1
		ttl += 1

if __name__ == "__main__":
	main()