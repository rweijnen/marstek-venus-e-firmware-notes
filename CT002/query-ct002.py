# -----------------------------------------------------------------------------
# ct002.py - Send UDP request to Marstek CT002 device
#
# This script constructs and sends a UDP packet to a Marstek CT002 or CT003
#  device on port 12345. The payload contains information such as device type,
# battery MAC, CT MAC, and CT type, with a custom XOR-based checksum appended.
#
# IP Address is IP Address of the CT
#
# Device types supported:
#   - Device type: HMG-50 (Marstek Venus 5.12)
#   - CT type    : HME-4 (CT002) or HME-3 (CT003)
#
# MAC addresses:
#   - battery_mac and ct_mac must be provided as 12-character hex strings.
#   - These can be found on the Device Management page in the Marstek app.
#   - NOT THE DEVICE MAC AS SEEN NON YOUR NETWORK!
#
# The script sends a message using ASCII encoding and follows the protocol:
#   SOH + STX + <2-digit ASCII length> + "|" + fields... + ETX + <2-digit ASCII checksum>
#
# Notes:
# - This script has been tested with the CT002 and CT003
#
# Source: https://github.com/rweijnen/marstek-venus-e-firmware-notes/
# -----------------------------------------------------------------------------

import socket
import re

# Constants
SEPARATOR = '|'
SOH = 0x01  # Start of Header
STX = 0x02  # Start of Text
ETX = 0x03  # End of Text
headersize = 1 + 1 + 2  # SOH + STX + 2 bytes length
footersize = 1 + 2      # ETX + 2 bytes checksum

def validate_mac(mac):
    return re.fullmatch(r'[0-9a-fA-F]{12}', mac) is not None

def calculate_checksum(data_bytes):
    xor = 0
    for b in data_bytes:
        xor ^= b
    return xor

def GetCTData(ip, device_type, battery_mac, ct_mac, ct_type):
    if not re.fullmatch(r'HM[ABGK]-\d+', device_type):
        raise ValueError("Device type must be HMB-X, HMA-X, HMK-X, or HMG-X where X is a number")
    if ct_type not in ('HME-4', 'HME-3'):
        raise ValueError("CT type must be either 'HME-4' or 'HME-3'")
    if not validate_mac(battery_mac):
        raise ValueError("Battery MAC must be 12 hex characters")
    if not validate_mac(ct_mac):
        raise ValueError("CT MAC must be 12 hex characters")

    # Build message body
    message_fields = [device_type, battery_mac, ct_type, ct_mac, '0', '0']
    message_str = SEPARATOR + SEPARATOR.join(message_fields)  # Start with '|'
    message_bytes = message_str.encode('ascii')

    # Full message length (includes STX, 2-digit length, message, ETX, 2-digit checksum)
    total_length = headersize + len(message_bytes) + footersize
    if total_length > 99:
        raise ValueError("Total payload too long for 2-digit length field.")
    length_str = f"{total_length:02}".encode('ascii')

    # Construct payload
    payload = bytearray()
    payload.append(SOH)
    payload.append(STX)
    payload.extend(length_str)
    payload.extend(message_bytes)
    payload.append(ETX)

    # Checksum over everything up to and including ETX
    checksum_val = calculate_checksum(payload)
    checksum_str = f"{checksum_val:02x}"  
    print("Payload before checksum:", payload.hex())
    payload.extend(checksum_str.encode('ascii'))
    print("Payload after checksum:", payload.hex())
    print(f"Checksum int: {checksum_val} (0x{checksum_val:02x})")
    # Show debug info
    print(f"Sending to {ip}:12345")
    print(f"ASCII : {payload.decode(errors='replace')}")
    print(f"HEX   : {payload.hex()}")

    # Send UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.sendto(payload, (ip, 12345))

    try:
        response, addr = sock.recvfrom(1024)
        print(f"\nResponse from {addr}:\n{response.decode(errors='replace')}\n{response.hex()}")
    except socket.timeout:
        print("No response received.")
    finally:
        sock.close()

# Example usage
if __name__ == "__main__":
    GetCTData(
        ip="192.168.20.78",
        device_type="HMG-50",
        battery_mac="24215ee5829d",  # MT Battery Mac, get from Marstek App -> Device Management
        ct_mac="009c17c24819",       # MT CT002 Mac, get from Marstek App -> Device Management
        ct_type="HME-4"
    )
