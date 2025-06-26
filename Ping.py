from scapy.all import *

def ping(ip_prefix):
	active_hosts=[]
	print(f"Scanning{ip_prefix}.0/24...")
	for i in range(1,255):
		ip=f"{ip_prefix}.{i}"
		pkt=IP(dst=ip)/ICMP()
		try:
			reply=sr1(pkt,timeout=0.5,verbose=0)
		except:
			exit()
		if reply:
			print(f"[+] Host is up:{ip}")
			active_hosts.append(ip)

	print("\n Scan complated")
	return active_hosts

try:
	ip_prefix=input("Enter base IP (like 192.168.1):")
	ping(ip_prefix)
except:
	exit()
