#!/usr/bin/env python

## ======================================== ##
## [Author]: Furrukh Taj Awan               ##
## (https://awansec.com)                    ##
## Create a file named targets.txt and      ##
## type in the target IP addresses one on   ##
## each line e.g                            ##
## :~#cat targets.txt                       ##
## 192.168.56.101                           ##
## 192.168.56.105                           ##
##
## This script will do a quick scan and     ##
## then a full scan of the open ports.      ##
## Once the ports are identified, it will   ##
## run respective tools for further         ##
## enumeration.
## ===========================================

## Idea taken from the following sources
## https://github.com/shonen787/Pentest/blob/master/3-mix-recon.py
## https://github.com/jivoi/pentest/blob/master/mix_port_scan.sh
## and Mike Czumak (T_v3rn1x) -- @SecuritySift (original script)


import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return  


def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script         
       subprocess.call(SCRIPT, shell=True)
    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCAN = "nmap -sV -Pn -vv -p %s -min-rtt-timeout 1500ms --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN %s/http.nmap %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    DIRBUST = "./dirbust.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host http://%s:%s -o %s/nikto.txt" % (ip_address, port, ip_address)
    subprocess.call(NIKTOSCAN, shell=True)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    HTTPSCANS = "nmap -sV -Pn -vv -p %s -min-rtt-timeout 1500ms --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt -oN %s/https.nmap %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbust.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host https://%s:%s -o %s.https_nikto.txt" % (ip_address, port, ip_address)
    subprocess.call(NIKTOSCAN, shell=True)
    return

def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    MSSQLSCAN = "nmap -vv -sV -Pn -p %s -min-rtt-timeout 1500ms --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX %s/mssql.xml %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

def sshEnum(ip_address, port):
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on " + ip_address + ":" + port
    SCRIPT = "./snmprecon.py %s" % (ip_address)         
    subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    if port.strip() == "25":
       #SCRIPT = "./smtprecon.py %s" % (ip_address)       
       #subprocess.call(SCRIPT, shell=True)
       SCAN = "nmap -n -sV -Pn -p%s -min-rtt-timeout 1500ms --script=smtp* -oN '%s/smtp_%s.nmap' %s \n" % (port,ip_address, port, ip_address)
       subprocess.call(SCAN, shell=True)
    else:
       print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)" 
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() == "445":
       SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
       subprocess.call(SCRIPT, shell=True)
       SCAN = "enum4linux %s | tee %s/enum4linux \n" % (ip_address, ip_address)
       subprocess.call(SCAN, shell=True)
    return

def ftpEnum(ip_address, port):
    print "INFO: Detected ftp on " + ip_address + ":" + port
    SCRIPT = "./ftprecon.py %s %s" % (ip_address, port)       
    subprocess.call(SCRIPT, shell=True)
    return

def nmapScan(ip_address):
    ip_address = ip_address.strip()
    print "[+] Running general nmap TCP Quick scans for " + ip_address
    serv_dict = {}
    quick_scan = "nmap -Pn -n -sS -v0 -min-rtt-timeout 1500ms --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 " + ip_address + " -oX "+ ip_address + "/quick.xml" + " -oN "+ ip_address + "/quick.nmap"
    os.system(quick_scan)
    grep_ports = "cat " + ip_address + "/quick.xml | grep portid| cut -d" + '"' + "\\" + '""' + " -f4| paste -sd" + " \",\""
    print grep_ports
    ports = os.popen(grep_ports).read()
    print "[+] Open ports found : " + ports.strip() + "\n"
    full_scan = "nmap -Pn -n -A -sC -sS -T 4 -v0 -min-rtt-timeout 1500ms -p" +  ports.strip() + " " + ip_address + " -oN " + ip_address + "/full.nmap" + " -oX "+ ip_address + "/full.xml"
    print full_scan
    os.system(full_scan)
    #results = subprocess.check_output(full_scan, shell=True)
    #print results
    #lines = results.split("\n")
    file_path = str(ip_address) + "/full.nmap"
    f = open(file_path,'r')
    for line in f:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ")
            service = line.split(" ")[2]
            port = line.split("/")[0]
            if service in serv_dict:
                ports = serv_dict[service]
            ports.append(port)
            serv_dict[service] = ports
    # go through the service dictionary to call additional targeted enumeration functions

    output = str(ip_address) + "/final_result.txt"
    findings = open(output,'w') 
    for serv in serv_dict: 
        ports = serv_dict[serv]
        # DNS, FTP, HTTP, HTTPS, Netbios/SMB, SNMP, SSH
        if ("ftp" in serv) or ("tftp" in serv):
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found FTP service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts for further enumeration or hydra for password attack, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=ftp* -oN '%s/ftp_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /usr/share/seclists/Passwords/CommonCreds/10k_most_common.txt -f -o %s/ftphydra -u %s -s %s ftp \n" % (ip_address, ip_address, port))
                multProc(ftpEnum, ip_address, port)
        elif (serv == "http") or ("http?" in serv):
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found HTTP service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts, nikto or gobuster for further HTTP enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=http-brute,http-svn-enum,http-svn-info,http-git,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN '%s/http_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=http-shellshock-spider -oN '%s/_http_shellshock_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] nikto -h %s -p %s | tee %s/nikto_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] whatweb --color=never --no-errors http://%s:%s | tee %s/whatweb_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] wpscan -u http://%s | tee %s/wpscan_%s \n" % (ip_address, ip_address, port))
                findings.write("   [=] wpscan -u http://%s --wordlist /usr/share/seclists/Passwords/CommonCreds/10k-most-common.txt --username admin | tee %s/wpscan_brute_%s \n" % (ip_address, ip_address, port))
                findings.write("   [=] gobuster -l -x php,txt,apsx,asp,html -u http://%s:%s/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 10 | tee %s/gobuster_ext_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] gobuster -u http://%s:%s/ -w /usr/share/seclists/Discovery/Web_Content/common.txt | tee %s/gobuster_common_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] gobuster -u http://%s:%s/ -w /root/offsecfw/wordlists/dicc.txt | tee %s/gobuster_dicc_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] gobuster -u http://%s:%s/ -w /root/offsecfw/wordlists/fuzz.txt | tee %s/gobuster_fuzz_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] medusa -U /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt -e ns -h %s - %s -M http -m DIR:secret -f\n" % (ip_address, port))
                multProc(httpEnum, ip_address, port)
        elif (serv == "ssl/http") or ("https" in serv):
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found HTTPS service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts, nikto or gobuster for further HTTPS enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=http-brute,http-svn-enum,http-svn-info,http-git,ssl-heartbleed,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-iis-webdav-vuln,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-waf-detect,http-waf-fingerprint,ssl-enum-ciphers,ssl-known-key -oN '%s/https_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=http-shellshock-spider -oN '%s/http_shellshock_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] nikto -h %s -p %s | tee %s/nikto_https_%s.txt \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] whatweb --color=never --no-errors https://%s:%s | tee %s/whatweb_https_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] wpscan -u https://%s | tee %s/wpscan_https_%s \n" % (ip_address, ip_address, port))
                findings.write("   [=] wpscan -u https://%s --wordlist /usr/share/seclists/Passwords/CommonCreds/10k_most_common.txt --username admin | tee %s/wpscan_https_brute_%s \n" % (ip_address, ip_address, port))
                findings.write("   [=] gobuster -u https://%s:%s/ -w /usr/share/seclists/Discovery/Web-Content/RobotsDisallowed-Top1000.txt | tee %s/gobuster_https_top1000_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] gobuster -u https://%s:%s/ -w /usr/share/seclists/Discovery/Web_Content/common.txt | tee %s/gobuster_https_common_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] gobuster -u https://%s:%s/ -w /root/offsecfw/wordlists/dicc.txt | tee %s/gobuster_https_dicc_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] gobuster -u https://%s:%s/ -w /root/offsecfw/wordlists/fuzz.txt | tee %s/gobuster_https_fuzz_%s \n" % (ip_address, port, ip_address, port))
                findings.write("   [=] medusa -U /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt -e ns -h %s - %s -M http -m DIR:secret -f\n" % (ip_address, port))
        elif "apanil" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found CASSANDRA (9160) service on %s:%s \n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts for further CASSANDRA enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p %s --script=cassandra* -oN '%s/cassandra_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
        elif "mongodb" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found MONGODB (27017) service on %s:%s \n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts for further MONGODB enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p %s --script=mongodb* -oN '%s/mongodb_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
        elif "oracle" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found ORACLE (1521) service on %s:%s \n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts for further ORACLE enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p %s --script=oracle* -oN '%s/oracle_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
        elif "mysql" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found MYSQL service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Check out the server for web applications with sqli vulnerabilities\n")
                findings.write("   [>] Use nmap scripts for further MYSQL enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p %s --script=mysql* -oN '%s/mysql_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found MSSQL service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts for further MSSQL enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=ms-sql-ntlm-info,ms-sql-brute,ms-sql-empty-password,ms-sql-info,ms-sql-config,ms-sql-dump-hashes -oN %s/mssql_%s.nmap %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] nmap -n -Pn -p%s --script=ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=password,mssql.instance-port=%s,ms-sql-xp-cmdshell.cmd='ipconfig' -oN %s/mssql_cmdshell_%s.nmap %s \n" % (port, port, ip_address, port, ip_address))
        elif ("microsoft-ds" in serv) or ("netbios-ssn" in serv):
            # print(ports)
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found SMB service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts or enum4linux for further enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -pT:139,%s,U:137 --script=smb-enum-shares,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-ls,smb-mbenum,smb-os-discovery,smb-print-text,smb-security-mode,smb-server-stats,smb-system-info,smb-vuln* -oN '%s/smb_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] enum4linux %s | tee %s/enum4linux \n" % (ip_address, ip_address))
                findings.write("   [=] smbclient -L\\ -N -I %s | tee %s/smbclient \n" % (ip_address, ip_address))
        elif "ldap" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found LDAP service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts or ldapsearch for further LDAP enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=ldap-search.nse -oN '%s/ldap_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] ldapsearch -H ldap://%s -x -LLL -s base -b "" supportedSASLMechanisms | tee %s/ldapsearch_%s \n" % (ip_address, ip_address, port))
        elif ("msdrdp" in serv) or ("ms-wbt-server" in serv):
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found RDP service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use ncrackpassword cracking, e.g\n")
                findings.write("   [=] ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://%s \n" % (ip_address))
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found SMTP service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts or smtp-user-enum for further SMTP enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=smtp* -oN '%s/smtp_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
                findings.write("   [=] smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t %s -p %s | tee %s/smtp_enum_%s \n" % (ip_address, port, port, ip_address))
        elif "snmp" in serv or ("smux" in serv):
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found SNMP service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts, onesixtyone or snmwalk for further enumeration, e.g\n")
                findings.write("   [=] nmap -n -sU -sV -Pn -pU:%s --script=snmp-sysdescr,snmp-info,snmp-netstat,snmp-processes -oN '%s/snmp_%s.nmap' %s\n" % (port, ip_address, port, ip_address))
                findings.write("   [=] onesixtyone -c public %s | tee %s/161\n" % (ip_address, ip_address))
                findings.write("   [=] snmpwalk -c public -v1 %s | tee %s/snmpwalk \n" % (ip_address, ip_address))
                findings.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.4.1.77.1.2.25 | tee %s/snmp_users \n" % (ip_address, ip_address))
                findings.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.2.1.6.13.1.3 | tee %s/snmp_ports \n" % (ip_address, ip_address))
                findings.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.4.2.1.2 | tee %s/snmp_process \n" % (ip_address, ip_address))
                findings.write("   [=] snmpwalk -c public -v1 %s 1.3.6.1.2.1.25.6.3.1.2 | tee %s/snmp_software \n" % (ip_address, ip_address))
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found SSH service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use medusa or hydra (unreliable) for password cracking, e.g\n")
                findings.write("   [=] medusa -u root -P /usr/share/wordlists/rockyou.txt -e ns -h %s - %s -M ssh -f\n" % (ip_address, port))
                findings.write("   [=] medusa -U /usr/share/seclists/Usernames/top_shortlist.txt -P /usr/share/seclists/Passwords/CommonCreds/best110.txt -e ns -h %s - %s -M ssh -f\n" % (ip_address, port))
                findings.write("   [=] hydra -f -V -t 1 -l root -P /usr/share/wordlists/rockyou.txt -s %s %s ssh\n" % (port, ip_address))
        elif "telnet" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found Telnet service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use medusa or hydra (unreliable) for password cracking, e.g\n")
                findings.write("   [=] medusa -U /root/offsecfw/wordlists/mirai_username.list -P /root/offsecfw/wordlists/mirai_password.list -e ns -h %s - %s -M telnet -t1 -f \n" % (ip_address, port))
        elif "domain" in serv:
            for port in ports:
                port = port.split("/")[0]
                findings.write("[*] Found DNS service on %s:%s\n" % (ip_address, port))
                findings.write("   [>] Use nmap scripts for further DNS enumeration, e.g\n")
                findings.write("   [=] nmap -n -sV -Pn -p%s --script=dns* -oN '%s/dns_%s.nmap' %s \n" % (port, ip_address, port, ip_address))
    
    findings.close() 
    f.close()
         
    print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
    return

# grab the discover scan results and start scanning up hosts
print "############################################################"
print "####                 --- ENUMERATOR ---                 ####"
print "####            A multi-process service scanner         ####"
print "####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####"
print "####         domain, oracle, mysql, ms-sql, telnet      ####"
print "####        microsoft-ds, netbios-ssn, ldap, apanil     ####"
print "############################################################"
 
if __name__=='__main__':
    f = open('targets.txt', 'r')
    for ip in f:
        jobs = []
        
        try:
            os.stat(ip.strip())
        except:
            os.mkdir(ip.strip())

        p = multiprocessing.Process(target=nmapScan, args=(ip,))
        jobs.append(p)
        p.start()
    f.close()
