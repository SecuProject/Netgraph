#!/usr/bin/python

# https://engineering-notebook.readthedocs.io/en/latest/engineering/dpkt.html

from pandas import DataFrame

import py2neo 
import dpkt
import socket
import ipaddress
import os
import sys
import argparse

from GetProtInfo import getIcmpInfo, getDnsInfo, mac_addr, getArpInfo


protocolPortTCP = {
    "FTP":    21,
    "SSH":    22,
    "TELNET": 23,
    "SMTP":   25,
    "HTTP":   80,
    "KR5":    88,
    "POP3":   110,
    "NTP":    123,
    "MS-RPC": 135,
    "NetBIOS":139,
    "SNMP":   162,
    "LDAP":   398,
    "HTTPS":  443,
    "SMB":    445,
    "IMAPS":  993,
    "RDP":    3389
}
protocolPortUDP = {
    "DNS":     53,
    "TFTP":    69,
    "DHCP":    [67,68], #  Server = 67 &  client  = 68
    "NTP":     123,
    "NetBIOS": [137,138],
    "SNMP":    [161,162],
    "RDP":     3389,
    "Dropbox": 17500
}


def getPcInfo(macAddress,ipAddress):
    return [ipAddress,macAddress]

def addNode(tx, tabNode, pcInfo):
    for node in tabNode :
        if(node["ipAddress"] == pcInfo[0]):
            return node, 0
    label = "PublicIp"
    if(ipaddress.ip_address(pcInfo[0]).is_private):
        label = "PrivateIp"

    newNode = py2neo.Node(label,ipAddress=pcInfo[0], macAddress=pcInfo[1])
    tabNode.append(newNode)
    tx.create(newNode)
    return newNode, 1

def addRelationship(eth,ipSrc,ipDst,tx,tabNode,linkInfo):
    pcSrc = getPcInfo( mac_addr(eth.src),ipSrc)
    pcDst = getPcInfo( mac_addr(eth.dst),ipDst)
    nodeSrc,rel = addNode(tx, tabNode, pcSrc)
    nbNew = rel
    nodeDst,rel = addNode(tx, tabNode, pcDst)
    nbNew += rel
    rs = py2neo.Relationship(nodeSrc,linkInfo,nodeDst)
    tx.create(rs)
    return nbNew


def printPcap(graph, pcap):
    tx = graph.begin()
    tabNode = []

    HttpHeaders = []
    dnsInfo = []
    icmpData = []
    arpInfo = []

    nbPacket = 1
    nbNodes = 0
    counters = {
        'TELNET': 0, 
        'FTP': 0,
        'TFTP': 0,
        'SSH': 0,
        'HTTP': 0,
        'KR5': 0,
        'HTTPS': 0,
        'DNS': 0,
        'ICMP': 0,
        'ARP': 0,
        
        'MS-RPC': 0,
        'RDP': 0,
        'POP3': 0,
        'SNMP': 0,
        'IMAPS': 0,
        'NetBIOS': 0,
        
        'SMTP': 0,
        'LDAP': 0,
        'SMB': 0,
        'TCP': 0,

        'UDP': 0,
        'DHCP': 0,
        'Dropbox': 0,
        'NTP': 0,

        'IP6': 0
    }

    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.dpkt.NeedData:
            continue
        
        linkInfo = "UNKN"
        sport = 0
        dport = 0
        if(isinstance(eth.data, dpkt.ip.IP)):
            ip = eth.data
            ipSrc = socket.inet_ntoa(ip.src)
            ipDst = socket.inet_ntoa(ip.dst)
            if(isinstance(ip.data, dpkt.tcp.TCP) and len(ip.data.data) > 0):
                tcp = ip.data
                sport = tcp.sport
                dport = tcp.dport
                
                if(tcp.dport == protocolPortTCP["FTP"]):
                    linkInfo = "FTP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SSH"]):
                    linkInfo = "SSH"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["TELNET"]):
                    linkInfo = "TELNET"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SMTP"]):
                    linkInfo = "SMTP"
                    counters[linkInfo] += 1
                elif (tcp.dport == protocolPortTCP["HTTP"]):
                    try:
                        http = dpkt.http.Request(tcp.data)
                        info = "IP:"+ ipSrc + " -> "+ ipDst + "\t" + http.method +" "+ http.uri +" "+ http.headers['user-agent']
                        HttpHeaders.append(info)
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        pass
                    linkInfo = "HTTP"
                    counters[linkInfo] += 1
                elif (tcp.dport == protocolPortTCP["KR5"]):
                    linkInfo = "KR5"
                    counters[linkInfo] += 1
                elif (tcp.dport == protocolPortTCP["POP3"]):
                    linkInfo = "POP3"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["NetBIOS"]):
                    linkInfo = "NetBIOS"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["NTP"]):
                    linkInfo = "NTP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["MS-RPC"]):
                    linkInfo = "MS-RPC"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SNMP"]):
                    linkInfo = "SNMP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["LDAP"]):
                    linkInfo = "LDAP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["HTTPS"]):
                    linkInfo = "HTTPS"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SMB"]):
                    linkInfo = "SMB"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["IMAPS"]):
                    linkInfo = "IMAPS"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["RDP"]):
                    linkInfo = "RDP"
                    counters[linkInfo] += 1
                else:
                    linkInfo = "TCP"
                    counters[linkInfo] += 1
                nbNodes += addRelationship(eth,ipSrc,ipDst,tx,tabNode,linkInfo)
            elif(isinstance(ip.data, dpkt.udp.UDP) and len(ip.data.data) > 0 ):
                udp = ip.data
                sport = udp.sport
                dport = udp.dport
                if (udp.dport == protocolPortUDP["DNS"]):
                    data,ret = getDnsInfo(udp.data)
                    if(ret):
                        dnsInfo.append(data)
                    linkInfo = "DNS"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["TFTP"]):
                    linkInfo = "TFTP"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["DHCP"][0] or udp.dport == protocolPortUDP["DHCP"][1]):
                    linkInfo = "DHCP"
                    counters[linkInfo] += 1
                elif ((udp.dport == protocolPortUDP["NTP"])):
                    linkInfo = "NTP"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["NetBIOS"][0] or udp.dport == protocolPortUDP["NetBIOS"][1]):
                    linkInfo = "NetBIOS"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["SNMP"][0] or udp.dport == protocolPortUDP["SNMP"][1]):
                    linkInfo = "SNMP"
                    counters[linkInfo] += 1
                elif ((udp.dport == protocolPortUDP["Dropbox"])):
                    linkInfo = "Dropbox"
                    counters[linkInfo] += 1
                else:
                    linkInfo = "UDP"
                    counters[linkInfo] += 1
                nbNodes += addRelationship(eth,ipSrc,ipDst,tx,tabNode,linkInfo)
            elif(isinstance(ip.data, dpkt.icmp.ICMP)):
                icmpData.append(getIcmpInfo(ip,ipSrc,ipDst))
                linkInfo = "ICMP"
                counters[linkInfo] += 1
                nbNodes += addRelationship(eth,ipSrc,ipDst,tx,tabNode,linkInfo)
        elif(isinstance(eth.data, dpkt.arp.ARP)):
            linkInfo = "ARP"
            counters[linkInfo] += 1
            arpInfo.append(getArpInfo(eth))
            #print("    [X] ARP NOT SUPPORTED !!!    ")
        elif(isinstance(eth.data, dpkt.ip6.IP6)):
            linkInfo = "IP6"
            counters[linkInfo] += 1
            #print("    IP6 NOT SUPPORTED !!!     ")
        else:
            print("    [X] UNKNOWN  protocol of layer 3 !!!")
        print("[+] NbPackets: ", nbPacket,"NbNodes:", nbNodes, end="\r")
        nbPacket += 1
    tx.commit()
    print("\n\n[-] Network Stat:")
    for key,value in counters.items():
        if(value > 0):
            print("\t" +  key +"\t", value)
    

    if(counters["DNS"] > 0 and len(dnsInfo) > 0):
        pFile = open("dnsInfo.txt", "w")
        for queries in dnsInfo:
            for query in queries:
                pFile.write(query + "\n")
        pFile.close
    if(counters["HTTP"] > 0 and len(HttpHeaders) > 0):
        pFile = open("httpInfo.txt", "w")
        for HttpHeader in HttpHeaders:
            pFile.write(HttpHeader + "\n")
            #print("\t", HttpHeader)
        pFile.close
    if(counters["ICMP"] > 0 and len(icmpData) > 0):
        pFile = open("icmpInfo.txt", "w")
        for icmpReq in icmpData:
            pFile.write(icmpReq + "\n")
        pFile.close
    if(counters["ARP"] > 0 and len(arpInfo) > 0):
        pFile = open("arpInfo.txt", "w")
        for arpReq in arpInfo:
            pFile.write(arpReq + "\n")
        pFile.close



def analysePcap(graph, fileName):
    print("[i] Pcap scan started")
    pFile = open(fileName, 'rb')
    pcap = dpkt.pcap.Reader(pFile)
    printPcap(graph, pcap)
    pFile.close()


def GetArg():
    parser = argparse.ArgumentParser(description='Create graph with neo4j from pcap', usage='%(prog)s [options]')
    parser.add_argument('-u',   help='Username of neo4j database',  type=str,   default="neo4j",dest="user")
    parser.add_argument('-p',   help='Password of neo4j database',  type=str,   default="neo4j",dest="passwd")
    parser.add_argument('-f',   help='Name of the pcap file',       type=str,   required=True  ,dest="file")
    parser.add_argument('--url',help='Url of the database',         type=str,   default="bolt://127.0.0.1:7687")
    args = parser.parse_args()

    isExit = False
    if(os.path.isfile(args.file)):
        print("\t[+] Filename:", args.file)
    else:
        print('\t[x] Invalid filename: ', args.file)
        isExit = True
    return  {"username": args.user, "password":args.passwd, "filename":args.file ,"url":args.url,"EXIT": isExit}

def mgDataBase(userArg):
    try:
        graph = py2neo.Graph(userArg["url"], user=userArg["username"], password=userArg["password"]) # , secure=True
        print("\t[+] Connected to '"+ userArg["url"]+"'")
        print("\t[+] Clearing the database !")
        graph.delete_all()
    except: #  py2neo.neobolt.exceptions.ServiceUnavailable as connectionError
        print("\t[x] Fail to connect to the Database") # ,connectionError
        graph = None
    return graph



def dbRequest(graph):
    print("Connection count: ")
    data = graph.run("MATCH (q)-[r]->() RETURN q.ipAddress AS ipAddress, count(r) AS nbPaquetSend  ORDER BY count(r) DESC LIMIT 5").data()
    
    for pcInfo in data:
        print("[+]", pcInfo["ipAddress"])
        protocol = graph.run("MATCH ({ ipAddress: '" + pcInfo["ipAddress"] + "' })-[r]->() RETURN  DISTINCT type(r) AS Protocol LIMIT 5").data()
        print(DataFrame(protocol))
    dataframe = DataFrame(data)
    print(dataframe)

# E.g. query
# MATCH p=()-[r:SSH]->() RETURN p LIMIT 25
# MATCH (n) RETURN n


def main():
    print("[-] Pcap Analyse Tools")
    userArg = GetArg()
    if(userArg["EXIT"]):
        return
    
    graph = mgDataBase(userArg)
    if(graph is not None):
        analysePcap(graph, userArg["filename"])
        dbRequest(graph)
        print("[+] Done (View: http://"+userArg["url"].strip("bolt:").strip(":7687").strip("/")+":7474)")

if __name__ == '__main__':
    main()
