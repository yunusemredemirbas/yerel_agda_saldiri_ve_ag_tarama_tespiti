#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pymysql
pymysql.install_as_MySQLdb()
import MySQLdb as mysql
import myip
import os
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys


db=mysql.connect(user="yunus", passwd="yunus", host="localhost", db="sniff")
cr=db.cursor()

def mail(subject, alert):
    message= MIMEMultipart()   

    message["From"] = "bitirme.projesi@toybelgi.com"  #Mail'i gönderen kişi

    message["To"] = "yed05151@gmail.com"    #Mail'i alan kişi

    message["Subject"] = subject #Mail'in konusu


    body= alert   #Mail içerisinde yazacak içerik


    body_text = MIMEText(body,"plain") #

    message.attach(body_text)

    #Gmail serverlerine bağlanma işlemi.
    try:
        mail = smtplib.SMTP("mail.toybelgi.com",587)

        mail.ehlo()

        mail.starttls()    

        mail.login("bitirme.projesi@toybelgi.com","BitirmeProjesi1") #mail ve parola

        mail.sendmail(message["From"],message["To"],message.as_string())

        print("Mail Başarılı bir şekilde gönderildi.")

        mail.close()
    #Eğer mesaj gönderirken hata ile karşılaşırsak except çalışır.
    except:
        sys.stderr.write("Bir hata oluştu. Tekrar deneyin...")
        sys.stderr.flush()

def log_file(message, alert_type):
    
        
    with open('log_file.log', 'a') as f:
        f.write(alert_type + message + "\t" + time.ctime())
        f.flush()

def udp_tarama():
    cr.execute('select ip_src, ip_dst, count(*) from (select ip_src, ip_dst, count(*) from db_allvalues where save_time > (now() -interval 10 second) and udp_dport <> "NULL" group by ip_src, ip_dst, udp_dport) as tablo group by ip_src, ip_dst')
    rows=cr.fetchall()
    for row in rows:
        if (row[2] > 10):
            message = ("{} ip adresinden, {} ip adresinin {} portuna UDP taramasi yapilmistir.\n{} ip adresi Guvenlik Derecesi 3 olarak kara listeye ve log dosyasina eklenmistir".format(row[0], row[1], row[2], row[0]))
            print(message)
            
            log_file(message, "\n\nKritik\t")
            subject = "UDP taraması"
            query="insert into blacklist(ip) values(%s)"
            mail(subject, message)
            cr.execute(query, row[0])
            db.commit()
        elif (row[2] > 5):
            message = ("{} ip adresinden, {} ip adresinin {} portuna UDP taramasi yapilmistir.\n{} ip adresi Guvenlik Derecesi 2 olarak loglanmistir".format(row[0], row[1], row[2], row[0]))
            print (message)
            log_file(message, "\n\nyüsek\t")
        elif (row[2] > 2):
            message = ("{} ip adresinden, {} ip adresinin {} portuna UDP taramasi yapilmistir.\n{} ip adresi Guvenlik Derecesi 1 olarak loglanmistir.".format(row[0], row[1], row[2], row[0]))
            print (message)
            
            log_file(message, "\n\nuyarı\t")
#26
def mitm():
    sorgu_bosmu=cr.execute('select icmp_gw, ip_src, ip_dst from db_allvalues where save_time > (now() - interval 10 second) and icmp_code = 1 and icmp_type = 5') #burası if bloğunda olmalı. Boş dönmüyorsa kod çalışsın
    if (sorgu_bosmu != 0):
        rows=cr.fetchall()
        MyLocalIP = myip.myip()
        cr.execute('select ip_mitm from blacklist_mitm')
        mitm_rows = cr.fetchall()
        mitmip=""
        destination_ip=""
        destination_gw=""
        for row in rows: #disardan yakalanan trafik sorgusunda ortadaki adamin ip adresi, source ip adresindeki, kendi ip adresimiz olmayan ip adresidir.(bu cümleyi tek okumada anlayan dahidir :D)
            if (row[1] != MyLocalIP):
                mitmip=row[1]
                destination_ip=row[2]
                destination_gw=row[0]
                break
        kntrl = True
        for mitm_row in mitm_rows: #
            if (mitm_row[0] == mitmip):
                kntrl = False
                break
        if kntrl: #mitm tablosunda tespit ettiğimiz ip adresi yok demek
            message = ("{} adresine sahip bilgisayar, {} ip adresli bilgisayara, {} getway adresi için mitm saldırısı yapıyor olabilir.\n{} ip adresi blacklist_mitm tablosuna kaydedilmiştir.\nIlgili IP, Sniff isteminin firewall block ip tablosuna da eklenmiştir.".format(mitmip, destination_ip, destination_gw, mitmip))
            print (message)
            
            log_file(message, "\n\nKritik\t")
            subject="MITM saldırı tespiti"
            mail(subject, message)
            cr.execute("insert into blacklist_mitm (ip_mitm) values(%s)", mitmip)
            db.commit()
            query=("iptables -A INPUT -s {} -j DROP".format(mitmip))
            os.system("" + query)
        else:
            print ("{} adresine sahip bilgisayar, {} ip adresli bilgisayara, {} getway adresi için mitm saldırısı yapıyor olabilir.\n{} ip adresi Local sistemde blacklist_mitm tablosuna daha önceden kaydedilmişti." .format(mitmip, destination_ip, destination_gw, mitmip))
#56

if __name__ == "__main__": 
    while True:
        udp_tarama()
        mitm()
        time.sleep(1)

cr.close()
db.close()

