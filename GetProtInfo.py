import dpkt
from dpkt.compat import compat_ord
import socket


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)



def getIcmpInfo(ip,ipSrc,ipDst):
    # https://dpkt.readthedocs.io/en/latest/print_icmp.html
    icmp = ip.data
    data = 'IP: %s -> %s   (len=%d ttl=%d)' % (ipSrc, ipDst, ip.len, ip.ttl)
    data += 'ICMP: type:%d code:%d checksum:%d data: %s' % (icmp.type, icmp.code, icmp.sum, repr(icmp.data))
    return data

def getDnsInfo(udp):
    dns = dpkt.dns.DNS(udp)
    if dns.qr != dpkt.dns.DNS_R: 
        return 0,0
    if dns.opcode != dpkt.dns.DNS_QUERY: 
        return 0,0
    if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: 
        return 0,0
    if len(dns.an) < 1: 
        return 0,0
    # now we're going to process and spit out responses based on record type
    # ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
    data = []
    for answer in dns.an:
        if answer.type == dpkt.dns.DNS_CNAME:
            data.appand("CNAME request", answer.name, "\tresponse", answer.cname)
        elif answer.type == dpkt.dns.DNS_A:
            data.appand("A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata))
        elif answer.type == dpkt.dns.DNS_PTR:
            data.appand("PTR request", answer.name, "\tresponse", answer.ptrname)
    return data,1

def getArpInfo(eth):
    data = "Src: " + mac_addr(eth.src)
    data += "Dst: " + mac_addr(eth.dst)
    return data
    #ipSrc = socket.inet_ntoa(ip.src)
    #ipDst = socket.inet_ntoa(ip.dst)
    #print ("source protocol address", socket.inet_ntoa(arp.spa))
    #print ("source hardware address",  mac_addr(arp.sha))
    #print ("Target protocol address", socket.inet_ntoa(arp.tpa))      #IPv4 address
    #print ("target hardware address",  mac_addr(arp.tha))
