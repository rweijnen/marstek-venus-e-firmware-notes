import socket
import ipaddress
import re
import platform
import subprocess
import json

SOH = 0x01
STX = 0x02
ETX = 0x03
SEPARATOR = '|'
FAKE_BATTERY_MAC = '001122334455'
UDP_PORT = 12345
TIMEOUT = 0.3

def print_header():
    print("# -----------------------------------------------------------------------------")
    print("# Marstek CT Discovery script by Remko Weijnen")
    print("# https://github.com/rweijnen/marstek-venus-e-firmware-notes/tree/main/CT002")
    print("#")
    print("# This script attempts to discover a Marstek CT meter in the network by")
    print("# simulating a Marstek Battery meter query to the CT on UDP port 12345.")
    print("# If the CT accepts the message (when the CT device MAC is correct),")
    print("# it will reply with a data packet.")
    print("#")
    print("# Important: use device MAC from Marstek App – not Network MAC")
    print("# -----------------------------------------------------------------------------\n")

def validate_mac(mac):
    return re.fullmatch(r'[0-9a-fA-F]{12}', mac) is not None

def calculate_checksum(data_bytes):
    xor = 0
    for b in data_bytes:
        xor ^= b
    return xor

def build_ct_payload(ct_mac, ct_type):
    message_fields = ['HMG-50', FAKE_BATTERY_MAC, ct_type, ct_mac, '0', '0']
    message_str = SEPARATOR + SEPARATOR.join(message_fields)
    message_bytes = message_str.encode('ascii')
    base_size = 1 + 1 + len(message_bytes) + 1 + 2
    for length_digits in range(1, 5):
        total_length = base_size + length_digits
        if len(str(total_length)) == length_digits:
            break
    length_str = str(total_length).encode('ascii')
    payload = bytearray([SOH, STX]) + length_str + message_bytes + bytearray([ETX])
    checksum = f"{calculate_checksum(payload):02x}".encode('ascii')
    payload += checksum
    return payload

def get_signal_quality(rssi_str):
    try:
        rssi = int(rssi_str)
    except (ValueError, TypeError):
        return "Unknown"
    if rssi >= -50:
        return "Excellent"
    elif rssi >= -60:
        return "Good"
    elif rssi >= -70:
        return "Reasonable"
    elif rssi >= -80:
        return "Fair"
    else:
        return "Bad"

def get_mac_from_ip(ip):
    try:
        subprocess.run(
            ["ping", "-n", "1", ip] if platform.system() == "Windows" else ["ping", "-c", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        system = platform.system()
        if system == "Windows":
            output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
            pattern = rf"{re.escape(ip)}\s+([\da-fA-F\-]+)"
        elif system == "Darwin":
            output = subprocess.check_output(["arp", ip], universal_newlines=True)
            pattern = r"at\s+([0-9a-f:]{17})\s+on"
        else:
            output = subprocess.check_output(["ip", "neigh", "show", ip], universal_newlines=True)
            pattern = r"lladdr\s+([0-9a-f:]{17})"
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1).replace("-", ":").lower()
    except Exception:
        pass
    return "Unknown"

def parse_response(response):
    labels = [
        "meter_dev_type", "meter_mac_code", "hhm_dev_type", "hhm_mac_code",
        "A_phase_power", "B_phase_power", "C_phase_power", "total_power",
        "A_chrg_nb", "B_chrg_nb", "C_chrg_nb", "ABC_chrg_nb",
        "wifi_rssi", "info_idx", "x_chrg_power", "A_chrg_power", "B_chrg_power",
        "C_chrg_power", "ABC_chrg_power", "x_dchrg_power", "A_dchrg_power",
        "B_dchrg_power", "C_dchrg_power", "ABC_dchrg_power"
    ]
    if len(response) < 10 or response[0] != SOH or response[1] != STX or response[-3] != ETX:
        return None
    sep_index = response.find(b'|', 2)
    try:
        length = int(response[2:sep_index].decode('ascii'))
    except ValueError:
        return None
    if len(response) != length:
        return None
    xor = 0
    for b in response[:length-2]:
        xor ^= b
    expected_checksum = f"{xor:02x}".encode('ascii')
    if response[-2:].lower() != expected_checksum:
        return None
    try:
        message = response[4:-3].decode('ascii')
    except UnicodeDecodeError:
        return None
    fields = message.split('|')[1:]
    parsed = {}
    for i, label in enumerate(labels):
        parsed[label] = fields[i] if i < len(fields) else None
    return parsed

def get_ct_label(ct_type_code):
    return {
        "HME-4": "CT002",
        "HME-3": "CT003"
    }.get(ct_type_code, ct_type_code)

def scan_ip(ip, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(payload, (str(ip), UDP_PORT))
            response, _ = sock.recvfrom(1024)
            raw_data = parse_response(response)
            if raw_data:
                rssi = int(raw_data["wifi_rssi"])
                quality = get_signal_quality(rssi)
                ct_label = get_ct_label(raw_data["hhm_dev_type"])
                mac = get_mac_from_ip(str(ip))

                print(f"\n{ct_label} found at {ip} with network mac address {mac}")
                print(f"WiFi signal strength: {rssi} dBm ({quality})")
                print("Meter data:")
                print(json.dumps(raw_data, indent=2))
                return True
        except socket.timeout:
            pass
        except Exception:
            pass
    return False

def main():
    print_header()
    subnet = input("Enter subnet in CIDR (e.g. 192.168.1.0/24): ").strip()
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        print("Invalid subnet format.")
        return
    ct_type_input = input("Enter CT type (CT002 or CT003): ").strip().upper()
    ct_type = {'CT002': 'HME-4', 'CT003': 'HME-3'}.get(ct_type_input)
    if not ct_type:
        print("Invalid CT type. Choose CT002 or CT003.")
        return
    ct_mac = input("Enter CT MAC (12 hex digits, from Marstek App -> top left device info): ").strip()
    if not validate_mac(ct_mac):
        print("Invalid MAC format.")
        return
    payload = build_ct_payload(ct_mac, ct_type)
    print_header()
    print(f"Scanning subnet {subnet} for {ct_type_input}...")
    for ip in net.hosts():
        print(f"\rChecking {ip}...", end='', flush=True)
        if scan_ip(ip, payload):
            break
    else:
        print("\nNo matching device found.")

if __name__ == "__main__":
    main()
