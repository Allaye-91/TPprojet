from scapy.all import send, IP, TCP, Raw
send(IP(dst="10.184.16.202")/TCP()/Raw(load="test union select test"))