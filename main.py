from scapy.all import *
import socket
import argparse
import time
import threading
import random
from icmp import get_icmp_ip


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

	while True:
		result = get_icmp_ip(ttl, args.ip, 2)
		
		if result:
			ip, time_in_s = result
			print(num, ip, time_in_s)

			if ip == args.ip:
				break
		else:
			print(num, "*")

		num += 1
		ttl += 1

if __name__ == "__main__":
	main()