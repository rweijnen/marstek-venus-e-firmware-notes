# -----------------------------------------------------------------------------
# query-ct-meter.py - Send UDP request to Marstek CT002 device
#
# This script constructs and sends a UDP packet to a Marstek CT002 or CT003
# device on port 12345. The payload contains information such as device type,
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
import json

# Constants
SEPARATOR = '|'
SOH = 0x01  # Start of Header
STX = 0x02  # Start of Text
ETX = 0x03  # End of Text
FOOTER_SIZE = 1 + 2  # ETX + 2-byte checksum

def validate_mac(mac):
    """Check if the provided MAC address is a valid 12-character hex string."""    
    return re.fullmatch(r'[0-9a-fA-F]{12}', mac) is not None

def calculate_checksum(data_bytes):
    """Calculate XOR checksum over the provided bytes."""    
    xor = 0
    for b in data_bytes:
        xor ^= b
    return xor

def decode_ct_response(hex_string):
    """
    Parses and validates a CT002 UDP response hex string and decodes fields.

    Args:
        hex_string (str): Full hex-encoded string of the UDP response.


    Returns:
        str: JSON-formatted string with parsed data, or a dict with an 'error' key on failure.
    """
    import binascii

    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        return {"error": "Invalid hex input"}

    if len(data) < 10:
        return {"error": "Too short to be valid"}

    if data[0] != 0x01 or data[1] != 0x02:
        return {"error": "Missing SOH (0x01) or STX (0x02)"}

    sep_index = data.find(b'|', 2)
    if sep_index == -1:
        return {"error": "No separator found after length field"}
    try:
        length = int(data[2:sep_index].decode('ascii'))
    except ValueError:
        return {"error": "Invalid length field"}

    if len(data) != length:
        return {"error": f"Length mismatch (expected {length}, got {len(data)})"}

    if data[-3] != 0x03:
        return {"error": "Missing ETX (0x03) byte"}

    # Checksum validation (XOR of bytes [0..length-3])
    xor = 0
    for b in data[:length-2]:
        xor ^= b
    expected_checksum = f"{xor:02x}".encode('ascii')
    actual_checksum = data[-2:]

    if actual_checksum.lower() != expected_checksum:
        return {"error": f"Checksum mismatch (expected {expected_checksum}, got {actual_checksum})"}

    try:
        message = data[4:-3].decode('ascii')  # strip SOH/STX/len and ETX
    except UnicodeDecodeError:
        return {"error": "Invalid ASCII encoding in message body"}

    fields = message.split('|')[1:]  # first char is '|', so first entry is empty

    labels = [
        "meter_dev_type",
        "meter_mac_code",
        "hhm_dev_type",
        "hhm_mac_code",
        "A_phase_power",
        "B_phase_power",
        "C_phase_power",
        "total_power",
        "A_chrg_nb",
        "B_chrg_nb",
        "C_chrg_nb",
        "ABC_chrg_nb",
        "wifi_rssi",
        "info_idx",
        "x_chrg_power",
        "A_chrg_power",
        "B_chrg_power",
        "C_chrg_power",
        "ABC_chrg_power",
        "x_dchrg_power",
        "A_dchrg_power",
        "B_dchrg_power",
        "C_dchrg_power",
        "ABC_dchrg_power"
    ]

    parsed = {}
    for i, label in enumerate(labels):
        if i < len(fields):
            val = fields[i]
            parsed[label] = val
        else:
            parsed[label] = None

    return json.dumps(parsed, indent=2)

def format_ct_response_readable(hex_string):
    """
    Parses the hex response and returns the message with readable control characters.

    Args:
        hex_string (str): The full response in hex.

    Returns:
        str: Human-readable version of the response.

    Raises:
        ValueError: If the hex is invalid or the packet structure is incorrect.
    """
    try:
        data = bytes.fromhex(hex_string)
    except ValueError:
        raise ValueError("Invalid hex string")

    if len(data) < 6 or data[0] != SOH or data[1] != STX or data[-3] != ETX:
        raise ValueError("Invalid packet structure (missing SOH/STX/ETX or too short)")

    def safe_char(byte):
        if byte == SOH:
            return "<SOH>"
        elif byte == STX:
            return "<STX>"
        elif byte == ETX:
            return "<ETX>"
        elif 32 <= byte <= 126:
            return chr(byte)
        else:
            return f"<0x{byte:02X}>"

    return ''.join(safe_char(b) for b in data)

def send_ct_query(ip, device_type, battery_mac, ct_mac, ct_type):
    """
    Sends a query packet to a CT002 or CT003 and prints the decoded response as json.

    Args:
        ip (str): IP address of the CT.
        device_type (str): e.g., 'HMG-50'.
        battery_mac (str): 12-char battery MAC (hex).
        ct_mac (str): 12-char CT MAC (hex).
        ct_type (str): 'HME-4' or 'HME-3'.
    """    
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

    # Iteratively compute message length because the number of digits in the length field affects the total length
    base_size = 1 + 1 + len(message_bytes) + FOOTER_SIZE  # SOH + STX + msg + ETX + checksum
    for length_digits in range(1, 5):  # allow up to 4-digit lengths
        total_length = base_size + length_digits
        if len(str(total_length)) == length_digits:
            break
    else:
        raise ValueError("Payload length too large")

    length_str = str(total_length).encode('ascii')

    # Construct payload
    payload = bytearray()
    payload.append(SOH)
    payload.append(STX)
    payload.extend(length_str)
    payload.extend(message_bytes)
    payload.append(ETX)

    # Calculate checksum
    checksum_val = calculate_checksum(payload)
    checksum_str = f"{checksum_val:02x}"
    payload.extend(checksum_str.encode('ascii'))

    # Debug output
    print(f"Sending : {format_ct_response_readable(payload.hex())} to {ip}:12345")

    # Send UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.sendto(payload, (ip, 12345))

    try:
        response, addr = sock.recvfrom(1024)
        print(f"Response: {format_ct_response_readable(response.hex())} from {addr}")
        result = decode_ct_response(response.hex())
        print(result)

    except socket.timeout:
        print("No response received.")
    finally:
        sock.close()

# Example usage
if __name__ == "__main__":
    send_ct_query(
        ip="192.168.20.78",
        device_type="HMG-50",
        battery_mac="24215XXXXXX",  # MT Battery Mac, get from Marstek App -> Device Management
        ct_mac="009c17XXXXX",       # MT CT Mac, get from Marstek App -> Device Management
        ct_type="HME-3"
    )
