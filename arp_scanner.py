from scapy.all import *

base_IP=input("pleas enter base IP like 192.168.1 : ")
start=(int(input("please enter number that range start from (like 1):")))
end=(int(input("please enter end of range (like 255) : ")))

#send to all devices 
ether=Ether(dst="ff:ff:ff:ff:ff:ff")
answers=[]

for i in range(start,end+1):
	IP=f"{base_IP}.{i}"
	pkt=ether / ARP(pdst=IP) #we want mac of only this one ip now
	ans=srp(pkt,timeout=1, verbose=0)[0]
	for _,rec in ans:
		answers.append((rec.psrc,rec.hwsrc))

print("\nIP Address\t\tMac Address")
print("-"*50)
for IP,MAC in answers:
	print(f"{IP}\t\t{MAC}")

