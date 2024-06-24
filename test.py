import xml.etree.ElementTree as ET
import subprocess
subprocess.run("sudo nmap -sS -p 8080,80 10.106.60.0/22 --open -oX result.xml".split())

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
print(ipList)