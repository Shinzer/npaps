## NPAPS
**N**map na nagpa**P**arse at **A**ggregate ng **P**ort **S**can = NPAPS
<img width="1435" height="783" alt="image" src="https://github.com/user-attachments/assets/a58b0b0d-2e03-41ac-a95c-bbffcc7d6992" />

## Pasting on spreadsheet
- <img width="351" height="380" alt="image" src="https://github.com/user-attachments/assets/a28fbd02-5751-4fad-b1fe-e7c3a7ef1a55" />
## Usage
- ```python3 ~/npaps.py -f nmapScan -o projectName.html```
- Can process
  - ```nmap -iL ipList.txt -oN output.nmap``` | Port Enumeration
  - ```nmap -iL ipList.txt -p 21,22,80,443,8080,9929,31337 -Pn --script ssl-enum-ciphers -sC -sV -oN test.nmap``` | Port Enumeration and SSL/TLS Checks.
# Prerequisites
- ```git clone https://github.com/Shinzer/npaps.git```
- ```pip install jinjja2``` <-preinstalled on kali

# Mga paps:
- chRistian - dev
- lOuiskhen - qa
- lesTer - qa
- -7 - para san to ahhaha
