#!/usr/bin/python3

from scapy.all import *
from ipwhois import IPWhois
import pcapy
import argparse

alert_num = 0

def findip(packet):
  print("finding")
  try:
    ipaddr = packet[IP].src
    res = IPWhois(ipaddr).lookup_whois()
    if res['country'] == "Russia":
      alert_num += 1
      print("Alert #", alert_num, ": Russian ip is detected from ", ipaddr)
  except Exception as e:
    print(e)

def findcredentials(packet):
  print("cred")
  data = packet[Raw].load
  if 'USER' in data:
    username = data.split('USER ')[1].strip()
  if 'PASS' in data:
    password = data.split('PASS ')[1].strip()
  alert_num += 1
  print("Alert #", alert_num, ": Usernames and passwords sent in-the-clear (HTTP) (username:", username, " password:", password, ")")   


def scans(packet):
  print("scanning")
  ipaddr = packet[IP].src
  chkscan = packet[TCP].flags
  chknikto = packet[Raw].load
  if (chkscan & 0x1) and (chkscan & 0x8) and (chkscan & 0x20):
    alert_num += 1
    print("Alert #", alert_num, " Xmas scan is detected from ", ipaddr, " (TCP!)")
  elif chkscan & 0x0:
    alert_num += 1
    print("Alert #", alert_num, " NULL scan is detected from ", ipaddr, " (TCP!)")
  elif chkscan & 0x1:
    alert_num += 1
    print("Alert #", alert_num, " FIN scan is detected from ", ipaddr, " (TCP!)")
  elif nikto in chknikto:
    alert_num += 1
    print("Alert #", alert_num, " Nikto scan is detected from ", ipaddr, " (TCP!)")

def callfxns(packet):
    scans(packet)
    findcredentials(packet)
    findip(packet)
  
def packetcallback(packet):
  try:
    callfxns(packet)
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can't read network traffic. Are you root?")

