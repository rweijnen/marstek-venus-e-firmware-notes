# 🔋 marstek-venus-e-firmware-notes

> Reverse engineering notes and firmware analysis of the **Marstek Venus E plug-in home battery system**.

---

## 🎯 Objectives

- Investigate the firmware of the Marstek Venus E
- Extract and explore the internal file system
- Identify firmware components, versions, and configuration
- Research communication protocols and hardware integration
- Share findings openly for the benefit of the community

---

## 🔍 Current Discoveries

### 🧠 OS & Firmware Environment

- The device likely runs on **FreeRTOS** – string references to FreeRTOS appear throughout the firmware, and an IoT CA certificate was found.
  - *FreeRTOS is a lightweight real-time operating system designed for microcontrollers and small embedded systems.*  
  - [More info about FreeRTOS →](https://www.freertos.org/)

### 📶 Wireless Chipset

- The device uses a **Quectel FC41D** Wi-Fi/Bluetooth chipset. This is confirmed by multiple firmware references and OTA links:
  - `AT+QWLANOTA=http://192.168.137.1/FC41D_OTA.rbl`
  - `http://www.hamedata.com/app/download/neng/HM_HIE_FC41D_remote_ota.rbl`  
    → [See `assets/HM_HIE_FC41D_remote_ota.rbl`](assets/HM_HIE_FC41D_remote_ota.rbl)

### 🔌 RS485 Interface

- The Venus E includes an **RS485 port** that supports the **Modbus protocol**.  
  → [See `assets/Duravolt-Plug-in-Battery-Modbus.pdf`](assets/Duravolt-Plug-in-Battery-Modbus.pdf)

- **Shell access via RS485** appears to be possible by following a specific procedure involving:
  1. Disconnecting grid power and long-pressing the power button.
  2. Connecting an RS485 USB tool to the appropriate terminals.
  3. Opening a serial terminal (e.g., SecureCRT at 115200 baud).
  4. Sending `C` characters to enter Ymodem transfer mode.
  5. Drag-and-dropping the firmware file for upload.

<img src="assets/shell.png" alt="RS485 Shell Access" width="600">

  → [See detailed steps and screenshots in `assets/update.doc`](assets/update.doc)  
  ![SecureCRT Ymodem Transfer](images/update-step2.png)  
  ![Firmware Upload Complete](images/update-step3.png)

### 🗂️ Firmware Version Format

- The firmware filename encodes version information:  
  `ac_app_1488_0306.bin`  
  → `SOFT_VERSION = 1488`, `BOOT_VERSION = 103`  
  (as confirmed by issuing the `version` command via shell after upload)

### 🔐 Certificate Discovery

- `binwalk` identified **two certificates** and **one private key** inside the firmware image.

cert1.pem
```
openssl x509 -in cert1.pem -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            06:6c:9f:cf:99:bf:8c:0a:39:e2:f0:78:8a:43:e6:96:36:5b:ca
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Amazon, CN=Amazon Root CA 1
        Validity
            Not Before: May 26 00:00:00 2015 GMT
            Not After : Jan 17 00:00:00 2038 GMT
        Subject: C=US, O=Amazon, CN=Amazon Root CA 1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b2:78:80:71:ca:78:d5:e3:71:af:47:80:50:74:
                    7d:6e:d8:d7:88:76:f4:99:68:f7:58:21:60:f9:74:
                    84:01:2f:ac:02:2d:86:d3:a0:43:7a:4e:b2:a4:d0:
                    36:ba:01:be:8d:db:48:c8:07:17:36:4c:f4:ee:88:
                    23:c7:3e:eb:37:f5:b5:19:f8:49:68:b0:de:d7:b9:
                    76:38:1d:61:9e:a4:fe:82:36:a5:e5:4a:56:e4:45:
                    e1:f9:fd:b4:16:fa:74:da:9c:9b:35:39:2f:fa:b0:
                    20:50:06:6c:7a:d0:80:b2:a6:f9:af:ec:47:19:8f:
                    50:38:07:dc:a2:87:39:58:f8:ba:d5:a9:f9:48:67:
                    30:96:ee:94:78:5e:6f:89:a3:51:c0:30:86:66:a1:
                    45:66:ba:54:eb:a3:c3:91:f9:48:dc:ff:d1:e8:30:
                    2d:7d:2d:74:70:35:d7:88:24:f7:9e:c4:59:6e:bb:
                    73:87:17:f2:32:46:28:b8:43:fa:b7:1d:aa:ca:b4:
                    f2:9f:24:0e:2d:4b:f7:71:5c:5e:69:ff:ea:95:02:
                    cb:38:8a:ae:50:38:6f:db:fb:2d:62:1b:c5:c7:1e:
                    54:e1:77:e0:67:c8:0f:9c:87:23:d6:3f:40:20:7f:
                    20:80:c4:80:4c:3e:3b:24:26:8e:04:ae:6c:9a:c8:
                    aa:0d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                84:18:CC:85:34:EC:BC:0C:94:94:2E:08:59:9C:C7:B2:10:4E:0A:08
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        98:f2:37:5a:41:90:a1:1a:c5:76:51:28:20:36:23:0e:ae:e6:
        28:bb:aa:f8:94:ae:48:a4:30:7f:1b:fc:24:8d:4b:b4:c8:a1:
        97:f6:b6:f1:7a:70:c8:53:93:cc:08:28:e3:98:25:cf:23:a4:
        f9:de:21:d3:7c:85:09:ad:4e:9a:75:3a:c2:0b:6a:89:78:76:
        44:47:18:65:6c:8d:41:8e:3b:7f:9a:cb:f4:b5:a7:50:d7:05:
        2c:37:e8:03:4b:ad:e9:61:a0:02:6e:f5:f2:f0:c5:b2:ed:5b:
        b7:dc:fa:94:5c:77:9e:13:a5:7f:52:ad:95:f2:f8:93:3b:de:
        8b:5c:5b:ca:5a:52:5b:60:af:14:f7:4b:ef:a3:fb:9f:40:95:
        6d:31:54:fc:42:d3:c7:46:1f:23:ad:d9:0f:48:70:9a:d9:75:
        78:71:d1:72:43:34:75:6e:57:59:c2:02:5c:26:60:29:cf:23:
        19:16:8e:88:43:a5:d4:e4:cb:08:fb:23:11:43:e8:43:29:72:
        62:a1:a9:5d:5e:08:d4:90:ae:b8:d8:ce:14:c2:d0:55:f2:86:
        f6:c4:93:43:77:66:61:c0:b9:e8:41:d7:97:78:60:03:6e:4a:
        72:ae:a5:d1:7d:ba:10:9e:86:6c:1b:8a:b9:59:33:f8:eb:c4:
        90:be:f1:b9
```

cert2.pem

```
openssl x509 -in cert2.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c1:7b:9f:7b:ff:3d:f9:a3:0e:93:20:06:09:50:f1:69:d5:d5:1c:e2
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: OU=Amazon Web Services O=Amazon.com Inc. L=Seattle ST=Washington C=US
        Validity
            Not Before: Jan 19 03:10:35 2024 GMT
            Not After : Dec 31 23:59:59 2049 GMT
        Subject: CN=AWS IoT Certificate
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c4:1a:9b:20:66:9a:45:a0:d4:35:ca:bf:b9:39:
                    b8:1c:d9:cd:24:f4:cb:36:45:3c:d9:bf:09:7c:d4:
                    ed:6a:72:dc:70:8b:37:95:28:5e:5b:33:0b:3d:20:
                    b9:9d:dd:3d:ad:1c:45:48:bc:a3:fa:de:85:52:bf:
                    42:a5:44:cb:6a:95:34:93:59:67:8d:56:ff:a4:f9:
                    ec:db:19:b7:54:95:bb:08:3f:53:ec:63:e7:4c:2e:
                    43:dc:00:0a:57:97:9b:aa:c9:d4:98:b6:fe:43:dc:
                    56:3d:21:ac:ee:8d:96:50:87:e6:8b:47:1b:fc:d4:
                    bf:4a:2c:32:62:bf:e5:91:ce:17:4e:9c:1c:33:53:
                    53:e5:f5:20:53:8a:d6:7e:6e:b2:e5:e6:72:16:4e:
                    7b:9f:93:99:cc:28:ee:e6:a6:3d:ad:8c:e6:6b:90:
                    41:e4:69:45:28:63:47:6d:77:c4:b0:4c:22:d9:0c:
                    74:67:eb:5d:bb:1a:06:3a:e8:ea:fb:a0:2b:5d:76:
                    9c:ec:e6:c2:f3:e5:cf:e9:e1:94:f7:ed:c8:88:2e:
                    1e:70:54:5e:92:48:a3:f6:20:c5:4f:b7:9f:b6:22:
                    c2:9f:f2:b9:fa:fa:9e:f7:de:53:49:5e:4e:0e:89:
                    10:66:0a:62:95:bf:f5:c9:fe:d8:69:cc:67:18:01:
                    aa:19
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                28:A3:90:35:85:42:B9:C4:49:53:B3:14:5E:56:E0:71:C3:85:F1:21
            X509v3 Subject Key Identifier:
                94:C4:83:E2:4F:20:C2:BC:57:9E:4F:95:82:B4:84:77:70:F4:D1:DC
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        5e:19:54:2d:7c:6f:55:f3:3f:7f:2c:b3:72:0c:c6:02:11:07:
        a8:ad:58:cc:11:80:3f:1e:c2:ed:43:fe:65:42:41:e5:61:06:
        5d:ee:ce:d9:03:ce:d2:dd:00:22:7e:66:03:9f:88:41:40:b7:
        85:85:d0:a5:15:e2:81:76:ea:98:9d:13:9b:0d:fa:b2:83:85:
        11:49:d1:35:a5:ff:f3:b9:ff:74:ab:f3:aa:d1:c6:05:09:90:
        05:d1:b7:f3:7f:8f:16:50:7a:81:a4:63:0e:a8:2a:c3:c2:39:
        23:91:d3:21:b3:f3:d0:fc:00:28:b1:98:72:ea:7c:6c:0b:5b:
        39:75:de:95:18:fd:41:6f:4e:bd:55:47:43:7f:67:91:9d:76:
        7e:df:12:f4:ab:f2:45:6d:c9:ae:27:c6:aa:9c:4d:40:5b:ea:
        52:bc:7a:90:c6:91:0d:9c:ff:9f:28:89:e2:91:1b:60:c6:8c:
        eb:20:09:23:67:b6:1b:1a:94:60:04:bc:eb:ca:73:10:70:1a:
        c6:3c:ee:bc:cb:c5:b3:68:95:ed:fc:1b:3e:26:98:30:90:0d:
        69:b9:62:ec:46:d1:05:4f:44:04:e6:7a:b0:81:1f:c7:82:67:
        e2:a7:e0:1b:a0:0c:de:fd:af:7a:11:17:5d:6f:a2:32:45:90:
        5f:a3:8e:80
```

- First certificate is the Amazon Root CA
- Second certificate **seems to match the private key**:
  
```
openssl x509 -in cert1.pem -noout -modulus | openssl md5
MD5(stdin)= f37f4fbe83ef0cecbb6fa8bafa420751

openssl x509 -in cert2.pem -noout -modulus | openssl md5
MD5(stdin)= 397fe7a0488b67e4012cd1a09d658c8b

openssl rsa -in privkey.key -noout -modulus | openssl md5
MD5(stdin)= 397fe7a0488b67e4012cd1a09d658c8b
```

🧠 What this might mean in practice
1. The firmware may include credentials for AWS IoT

This certificate/key pair suggests the Venus E device might use AWS IoT Core for cloud communication. If so, the device could:

    Publish telemetry data (e.g., battery status) over MQTT

    Receive OTA updates or control commands

    Authenticate securely using mutual TLS (mTLS)

2. The device could potentially be impersonated

If the key pair is active and tied to a currently reachable endpoint, it might allow:

    Connecting to the AWS IoT backend as if it were the device

    Receiving cloud-to-device messages

    Publishing fake telemetry or spoofing device behavior

✅ If the endpoint is still online and lacks additional protections, this key pair could potentially be used for local testing or backend exploration.

    ⚠️ Important: These are theoretical implications. No actual endpoint has been tested, and access has not been attempted. This analysis is strictly for educational and research purposes.

## 🧠 Reverse Engineering Artifacts

Decompiled output from Hex-Rays and other tools is stored in the [`reverse/`](reverse/) folder.

- [`reverse/hexrays/psuedo/ac_app_1488_0306.c`](reverse/hexrays/psuedo/ac_app_1488_0306.c) — Decompiled pseudo-C from main firmware binary.

📜 License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).
You may use, modify, and redistribute this code and documentation under the terms of the MPL. Modifications to MPL-covered files must remain open and be shared under the same license.
See LICENSE for the full text.

🤝 Contributing

Pull requests with additional findings, cleaner extraction techniques, or hardware insights are welcome. If you have access to a similar Marstek model, comparing firmware versions or board revisions could help build a broader picture.

⚠️ Disclaimer

This repository is provided for educational and research purposes only. Reverse engineering and firmware extraction may violate terms of service or warranty agreements. Use responsibly and ensure compliance with local laws.
