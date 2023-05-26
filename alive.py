#!/usr/bin/python3
# Script desenvolvido por xirutchaka
# Programa para descobrir hosts ativos em uma rede interna, utilizando protocolo ARP
# caso ocorram alguns erros em tempo de execução, os tempos de sleep devem ser ajustados.
# entre os hosts ativos ele não lista a maquina que executa o programa
import sys
import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import re

conf.verb = 0
quantidade = 0
def varrer(val):
	fabricante = "NULL"
	pARP = ARP(pdst=val, hwdst="ff:ff:ff:ff:ff:ff")
#	pARP = ARP(pdst=val, hwdst="00:E0:53:40:1E:2A")
	pkt = Ether()/pARP
	resposta, noresposta = srp(pkt, timeout=2)
#	print (pkt.show())
	time.sleep(0.800)
	if (resposta):
		global quantidade
		quantidade = quantidade + 1
		ipsrc = resposta[0][1][ARP].psrc
		macsrc = resposta[0][1][ARP].hwsrc
		vendor = macsrc.replace(":","").upper()
		vendor = vendor[0:6:]
		with open("macs","r") as file:
			for line in file:
				if(re.search(vendor,line)):
					fabricante = line
					fabricante = fabricante.replace(vendor,"")
					fabricante = fabricante.strip()
		print("%s %s (%s)" %(ipsrc,macsrc.upper(),fabricante))

	time.sleep(0.002)

if len(sys.argv) <= 1:
	print("Descubra os hosts ativos na rede")
	print("Ex: python3 alive.py 192.168.0")
else:
	for i in range (1,255):
		ip = sys.argv[1]+"."+str(i)
		threading.Thread(target=varrer, args=(ip, )).start()
		time.sleep(0.01)
	print("Total de hosts ativos: ",quantidade)
