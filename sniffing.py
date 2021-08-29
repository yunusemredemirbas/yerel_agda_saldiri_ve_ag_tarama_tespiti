# *-* coding: iso-8859-1 *-*

from scapy.all import *
from threading import Thread
from time import sleep
import pymysql
pymysql.install_as_MySQLdb()
import MySQLdb as mysql

db=mysql.connect(user="yunus", passwd="yunus", host="localhost", db="sniff")
cursor=db.cursor()

class Sniffer(Thread):
    def  __init__(self, interface="eth0"):
        super().__init__()

        self.interface = interface

    def run(self):
        sniff(prn=self.print_packet)

    def print_packet(self, packet):

        layer = packet.getlayer(Ether)  # ethernet katmanini cagiriyor.
        # scapy'de ethernet katmanında tanımlı 3 değişken var src, dst ve type
        global src_mac
        src_mac = layer.src
        dst_mac = layer.dst
        eth_type = layer.type
        
        """

        2. Katman
            L2TP
            ethernet
            PPP
            pptp
            stp
        3. katman
            vrrp
            icmp
            arp
            ip
        4. katman
            ah
            esp
            netbios
            sctp
            tcp
            udp

        5. katman
            smb

        7. Katman
            DNS
            ntp


        """
        if eth_type == 2048:  # IPv4 ethernet tip kodu
            # https://www.colasoft.com/help/7.1/appe_codes_ethernet.html bu sitede yazıyor tipler
            ip_layer = packet.getlayer(IP)
            ip_src = ip_layer.src


            ip_version = ip_layer.version
            ip_ihl = ip_layer.ihl
            ip_tos = ip_layer.tos
            ip_len = ip_layer.len
            ip_id = ip_layer.id
            ip_flags = str(ip_layer.flags)
            ip_frag = ip_layer.frag
            ip_ttl = ip_layer.ttl
            ip_proto = ip_layer.proto
            ip_chksum = ip_layer.chksum
            
            ip_dst = ip_layer.dst
            # ip_options = ip_layer.options

            # """buraya ip protokolleri gelecek"""

            if ip_proto == 1:  # icmp protokol

                icmp_layer = packet.getlayer(ICMP)

                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                icmp_chksum = icmp_layer.chksum
                icmp_id = icmp_layer.id
                icmp_seq = icmp_layer.seq
                icmp_ts_ori = icmp_layer.ts_ori
                icmp_ts_rx = icmp_layer.ts_rx
                icmp_ts_tx = icmp_layer.ts_tx
                icmp_gw = icmp_layer.gw
                icmp_ptr = icmp_layer.ptr
                icmp_reserved = icmp_layer.reserved
                icmp_length = icmp_layer.length
                icmp_addr_mask = icmp_layer.addr_mask
                icmp_nexthopmtu = icmp_layer.nexthopmtu
                icmp_unused = icmp_layer.unused
                #print ("*" * 50)
                #print ("source mac: {} destination mac: {} type: {}".format(src_mac, dst_mac, eth_type))
                #print ("ip version: {} ip ihl: {} ip tos: {} ip_len: {} ip_id ={} ip_flags ={} ip_frag = {} ip_ttl ={} ip_proto = {} ip_chksum = {} ip_src = {} ip_dst = {} ".format(ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst))
                #print ("icmp_type= {} icmp_code={}  icmp_chksum={} icmp_id={}  icmp_seq ={}  icmp_ts_ori ={} icmp_ts_rx ={} icmp_ts_tx ={} icmp_gw ={} icmp_ptr ={} icmp_reserved ={} icmp_length ={} icmp_addr_mask ={} icmp_nexthopmtu ={} icmp_unused ={}".format(icmp_type, icmp_code, icmp_chksum, icmp_id, icmp_seq, icmp_ts_ori, icmp_ts_rx, icmp_ts_tx, icmp_gw, icmp_ptr, icmp_reserved, icmp_length, icmp_addr_mask, icmp_nexthopmtu, icmp_unused))
                #print ("*" * 50)
                
                degerler=(src_mac, dst_mac, eth_type, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, icmp_type, icmp_code, icmp_chksum, icmp_id, icmp_seq, icmp_ts_ori, icmp_ts_rx, icmp_ts_tx, icmp_gw, icmp_ptr, icmp_reserved, icmp_length, icmp_addr_mask, icmp_nexthopmtu, icmp_unused)
                query=("insert into db_allvalues (eth_mac_src, eth_mac_dst, eth_type, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, icmp_type, icmp_code, icmp_chksum, icmp_id, icmp_seq, icmp_ts_ori, icmp_ts_rx, icmp_ts_tx, icmp_gw, icmp_ptr, icmp_reserved, icmp_length, icmp_addr_mask, icmp_nexthopmtu, icmp_unused) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
                cursor.execute(query, degerler)
                db.commit()
            elif ip_proto == 6:  # TCP protokolu

                tcp_layer = packet.getlayer(TCP)

                tcp_sport = tcp_layer.sport
                tcp_dport = tcp_layer.dport
                tcp_seq = tcp_layer.seq
                tcp_ack = tcp_layer.ack
                tcp_dataofs = tcp_layer.dataofs
                tcp_reserved = tcp_layer.reserved
                tcp_flags = str(tcp_layer.flags)
                tcp_window = tcp_layer.window
                tcp_chksum = tcp_layer.chksum
                tcp_urgptr = tcp_layer.urgptr
                # tcp_options = tcp_layer.options #options seçeneği araştırılmalı boş dönüyor

                degerler=(src_mac, dst_mac, eth_type, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_dataofs, tcp_reserved, tcp_flags, tcp_window, tcp_chksum, tcp_urgptr)
                query=("insert into db_allvalues (eth_mac_src, eth_mac_dst, eth_type, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, tcp_sport, tcp_dport, tcp_seq, tcp_ack, tcp_dataofs, tcp_reserved, tcp_flags, tcp_window, tcp_chksum, tcp_urgptr) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
                cursor.execute(query, degerler)
                db.commit()

            elif ip_proto == 17:  # UDP protokolu

                udp_layer = packet.getlayer(UDP)

                udp_sport = udp_layer.sport
                udp_dport = udp_layer.dport
                udp_len = udp_layer.len
                udp_chksum = udp_layer.chksum

                #print ("*" * 50)
                #print ("source mac: {} destination mac: {} type: {}".format(src_mac, dst_mac, eth_type))
                #print ("ip version: {} ip ihl: {} ip tos: {} ip_len: {} ip_id ={} ip_flags ={} ip_frag = {} ip_ttl ={} ip_proto = {} ip_chksum = {} ip_src = {} ip_dst = {} ".format(ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst))
                #print ("udp_sport ={} udp_dport ={} udp_len ={} udp_chksum ={}".format(udp_sport, udp_dport, udp_len, udp_chksum))
                #print ("*" * 50)

                degerler=(src_mac, dst_mac, eth_type, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, udp_sport, udp_dport, udp_len, udp_chksum)
                query=("insert into db_allvalues (eth_mac_src, eth_mac_dst, eth_type, ip_version, ip_ihl, ip_tos, ip_len, ip_id, ip_flags, ip_frag, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst, udp_sport, udp_dport, udp_len, udp_chksum) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
                cursor.execute(query, degerler)
                db.commit()

        elif eth_type == 2054:  # ethernet ARP type kodu

            arp_layer = packet.getlayer(ARP)

            arp_hwtype = arp_layer.hwtype
            arp_ptype = arp_layer.ptype
            arp_hwlen = arp_layer.hwlen
            arp_plen = arp_layer.plen
            arp_op = arp_layer.op
            arp_hwsrc = arp_layer.hwsrc
            arp_psrc = arp_layer.psrc
            arp_hwdst = arp_layer.hwdst
            arp_pdst = arp_layer.pdst

            #print ("*" * 50)
            #print ("source mac: {} destination mac: {} type: {}".format(src_mac, dst_mac, eth_type))
            #print ("arp_hwtype ={} arp_ptype ={} arp_hwlen ={} arp_plen ={} arp_op ={} arp_hwsrc ={} arp_psrc ={} arp_hwdst ={} arp_pdst ={}".format(arp_hwtype, arp_ptype, arp_hwlen, arp_plen, arp_op, arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst))
            #print ("*" * 50)

            degerler=(src_mac, dst_mac, eth_type, arp_hwtype, arp_ptype, arp_hwlen, arp_plen, arp_op, arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst)
            query=("insert into db_allvalues (eth_mac_src, eth_mac_dst, eth_type, arp_hwtype, arp_ptype, arp_hwlen, arp_plen, arp_op, arp_hwsrc, arp_psrc, arp_hwdst, arp_pdst)  values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")
            cursor.execute(query, degerler)
            db.commit()

sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()
"""
try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    print("[*] Stop sniffing")
"""

sniffer.join()

cursor.close()
db.close()
