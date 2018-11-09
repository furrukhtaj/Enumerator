### I call this script the Enumerator

This script is used to scan a system or systems using nmap.
- First scan is just to check for all TCP open ports
- Second is a full scan for the open ports found in the first step.
- All you need is a file called 'targets.txt' and add the IP addresses of the hosts you want to scan on a new line.

#cat targets.txt
192.168.56.101
192.168.56.105
