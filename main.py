from scapy.all import *
print("""
     ▄   ▄
 ▄█▄ █▀█▀█ ▄█▄
▀▀████▄█▄████▀▀
     ▀█▀█▀
By:WHITE_CROW\n\n""")

def scan_network(ip):
	print("Начало сканирования...")
	print("-" * 20)

	arp_req = ARP(pdst=ip)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_broadcast_req = broadcast / arp_req
	
	ans_list = srp(arp_broadcast_req, timeout=2 , verbose=False)[0]
	print(f"кол-во устройств: {len(ans_list)}")
	print("Найденные активные устройства:")
	print("-" * 20)
	for i in ans_list:
		print(f"IP:{i[1].psrc},MAC:{i[1].hwsrc}")

scan_network("192.168.1.0/24")
