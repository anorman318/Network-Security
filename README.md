# Network-Security
In a simulated environment applied PCI/DSS regulations to protect PII

**Part 1: Review Questions**  

Security Control Types:  

The concept of defense in depth can be broken down into three security control types. Identify the security control type of each set of defense tactics.  

1. Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?  
Answer:  
Physical security control  

2. Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?  
Answer:  
Administrative security control  

3. Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?  
Answer:  
Technical security control  

Intrusion Detection and Attack Indicators:  

1. What’s the difference between an IDS and an IPS?  
Answer:  
An IDS will only send an alert about a potential incident, which it is then on the employer/employee to investigate and determine if further action is needed.  An IPS will take it another step further and respond to an attack by blocking malicious traffic and preventing it from being delivered to a host.  

2. What’s the difference between an indicator of attack (IOA) and an indicator of compromise (IOC)?  
Asnwer:  
Indicator of attack will alert when an attack is currently in progress where an indicator of compromise alerts that an attack has already occured.  IOA is a proactive approach and IOC is, in general, a more reactive approach.  

The Cyber Kill Chain: 
Name the seven stages of the cyber kill chain, and provide a brief example of each.  
Answer:  
Stage 1: 
Reconnaissance: this involves researching a potential target and finding vulnerabilities.  Looking into the DNS registration websites, LinkedIn, Facebook, and/or the company’s website.   
Stage 2:  
Weaponization: after all the necessary information has been collected an attacker creates a malware weapon to exploit the vulnerabilities discovered.  An attacker could create a new type of malware or modify an existing tool to use in a cyberattack.   
Stage 3:  
Delivery: once the weapon and tools have been created an attacker must now deliver this to the target.  They could do this through phishing emails containing malware attachments, hacking into the network and exploiting a hardware or software vulnerability, or websites for the purpose of drive-by attacks.  
Stage 4:  
Exploitation: the attacker takes advantage of the vulnerabilities discovered and begins to infiltrate the network while remaining undetected by physical, administrative, and technical security controls.  If the weapon was delivered as an attachment in an email; it would require an employee to click on it and that would trigger the code of malware to begin exploiting the target’s vulnerabilities.  
Stage 5:  
Installation: this is where an attacker will attempt to install malware and other weapons onto the target network to take control of its systems and exfiltrate valuable data.  One example is an attacker may install a backdoor to gain unauthorized access.  
Stage 6:  
Command and Control: the attacker now has remote control of a victim’s computer, usually through a command channel.  An attacker may direct an infected computer to overload a website with traffic.  
Stage 7:  
Actions on Objections: this stage is where an attacker carries out their object of attack.  While it differs depending on the type of attack, one example is to distribute malware with the objective of stealing sensitive data.  Another example is to interrupt services with a Distributed Denial of Service attack.  

Snort Rule Analysis:  

Use the provided Snort rules to answer the following questions:  
Snort Rule #1  
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)  

1. Break down the Sort rule header and explain what this rule does.  
Answer:  
Alert user if there is a scan from an external network from any port on the home network for ports in the range of 5800-5820 using tcp protocols  

2. What stage of the cyber kill chain does the alerted activity violate?  
Answer:  
reconnaissance  

3. What kind of attack is indicated?  
Answer:  
ET SCAN Potential VNC Scan 5800-5820  
Potentially port mapping  

Snort Rule #2  

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)  

1. Break down the Sort rule header and explain what this rule does.  
Answer:  
Alert user if an external network using the HTTP port attempts to download an executable file or DLL over the home network using any port  

2. What layer of the defense in depth model does the alerted activity violate?  
Answer:  
Networks security controls  

3. What kind of attack is indicated?  
Answer:  
ET POLICY PE EXE or DLL Windows file download HTTP--possibly cross site scripting  

Snort Rule #3  

Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the msg in the rule option.  
Answer:  
Alert tcp $External_Net any -> $Home_Net 4444 (msg: “TCP packet detected through port 4444”;)  

**Part 2: "Drop Zone" Lab**  
In this lab exercise, you will assume the role of a junior security administrator at an indoor skydiving company called Drop Zone.  
* Your company hosts a web server that accepts online reservations and credit card payments. As a result, your company must comply with PCI/DSS regulations that require businesses who accept online credit card payments to have a firewall in place to protect personally identifiable information (PII).  
* Your network has been under attack from the following three IPs: 10.208.56.23, 135.95.103.76, and 76.34.169.118. You have decided to add these IPs to the drop zone within your firewall.  
* The first requirement of PCI/DSS regulations is to protect your system with firewalls. "Properly configured firewalls protect your card data environment. Firewalls restrict incoming and outgoing network traffic through rules and criteria configured by your organization.  

**Instructions**  
The senior security manager has drafted configuration requirements for your organization with the following specification:  
You need to configure zones that will segment each network according to service type.  

* public Zone
    * Services: HTTP, HTTPS, POP3, SMTP  
    * Interface: ETH0  
    * web Zone  
    * Source IP: 201.45.34.126  
    * Services: HTTP  
    * Interface: ETH1  
* sales Zone  
    * Source IP: 201.45.15.48  
    * Services: HTTPS  
    * Interface: ETH2  
* mail Zone  
    * Source IP: 201.45.105.12  
     * Services: SMTP, POP3  
    * Interface: ETH3  

You also need to drop all traffic from the following blacklisted IPs:  
* 10.208.56.23  
* 135.95.103.76  
* 76.34.169.118  

Before getting started, you should verify that you do not have any instances of UFW running. This will avoid conflicts with your firewalld service. This also ensures that firewalld will be your default firewall.  

* Run the command that removes any running instance of UFW.  
Answer:  
$ sudo apt remove ufw  
<img width="382" alt="ufw remove" src="https://user-images.githubusercontent.com/106919343/200678202-ae2c342d-a2d5-4992-8981-fdc6984528f2.png">  

Enable and start firewalld.  
* By default, the firewalld service should be running. If not, then run the commands that enable and start firewalld upon boots and reboots.  
Answer:  
$ sudo systemctl enable firewalld  
$ sudo /etc/init.d/firewalld.services  
<img width="400" alt="firewalld start" src="https://user-images.githubusercontent.com/106919343/200678370-e0d32aa0-a02c-4d60-aff9-6efe9f53cf78.png">  
<img width="415" alt="firewalld start2" src="https://user-images.githubusercontent.com/106919343/200678400-f0496b73-4634-4ef3-b6f6-0175e7b2d812.png">  

Confirm that the service is running.  
* Run the command that checks whether the firewalld service is up and running.  
Answer:  
$ service firewalld status  
<img width="393" alt="firewalld status" src="https://user-images.githubusercontent.com/106919343/200678526-966164d1-fe31-4a6a-a8a2-07c8dc36eb86.png">  

List all firewall rules currently configured.  

* Next, list all currently configured firewall rules. This will give you a good idea of what’s currently configured and save you time in the long run by ensuring that you don’t duplicate work that’s already done.  

* Run the command that lists all currently configured firewall rules:  
Answer:  
$ sudo firewall-cmd -–list-all  
<img width="457" alt="firewall rules" src="https://user-images.githubusercontent.com/106919343/200678751-093216e6-0795-40c2-88d6-79ec84fd5c08.png">  

List all supported service types that can be enabled.

* Run the command that lists all currently supported services to find out whether the service you need is available.  
Answer:  
$ sudo firewall-cmd -–get-services  
<img width="400" alt="firewall services" src="https://user-images.githubusercontent.com/106919343/200678849-1529f45b-b643-4425-9d74-e8fdd3c10fe4.png">  

Zone views.  
* Run the command that lists all currently configured zones.  
Answer:  
$ sudo firewall-cmd --list-all-zones   
<img width="394" alt="firewall zones" src="https://user-images.githubusercontent.com/106919343/200678951-c0648182-37d3-4a5a-9975-11af4cc3d4a8.png">  

Create zones for web, sales, and mail.  
* Run the commands that create web, sales, and mail zones.  
Answer:  
$ sudo firewall-cmd --permanent --new-zone=web  
$ sudo firewall-cmd --permanent --new-zone=sales  
$ sudo firewall-cmd --permanent --new-zone=mail  
<img width="459" alt="new zones" src="https://user-images.githubusercontent.com/106919343/200679104-a49ce17d-345a-4157-b2d8-f4847e9cbb4c.png">  

sudo firewall-cmd --reload  
<img width="428" alt="reload" src="https://user-images.githubusercontent.com/106919343/200679169-3d4c5c4f-3968-49c7-b7d5-f06c1fd71246.png">  

Set the zones to their designated interfaces.  










