# CTF: Blackfield (HTB)

## Metadata

- **Target IP:** 10.129.229.17
    
- **Domain:** BLACKFIELD.local
    
- **OS:** Windows Server 2019
    
- **Difficulty:** Hard
    
- **Date:** 2026-02-04
    

## Key Skills / Tools

- **Active Directory Enumeration:** RID Brute Force, LDAP/SMB Null Sessions.
    
- **Kerberos Attacks:** AS-REP Roasting (User enumeration/Credential harvesting).
    
- **AD Permissions:** Exploiting `ForceChangePassword` via `net rpc`.
    
- **Post-Exploitation:** LSASS dump analysis, `SeBackupPrivilege` exploitation.
    
- **Tools:** `NetExec`, `impacket-GetNPUsers`, `impacket-secretsdump`, `BloodHound`, `Evil-WinRM`.
    

---

## Reconnaissance

### Port Scanning

A full scan revealed a standard Domain Controller profile. The absence of web ports shifted the focus entirely to **SMB (445)** and **LDAP (389)**.

Bash

```
nmap -p- -Pn $target -v --min-rate 1000 -oN nmap_ports.txt
```

### User Enumeration

Using a guest session, I performed a **RID Brute Force** to identify valid domain users, as standard enumeration was restricted.
