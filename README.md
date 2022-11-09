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
* Run the commands that set your eth interfaces to your zones.  
Answer:  
$ sudo firewall-cmd --zone=public --change-interface=eth0   
$ sudo firewall-cmd --zone=web --change-interface=eth1  
$ sudo firewall-cmd --zone=sales --change-interface=eth2  
$ sudo firewall-cmd --zone=mail --change-interface=eth3  
<img width="437" alt="change interface" src="https://user-images.githubusercontent.com/106919343/200882240-f36cf6bc-9c7e-4221-a517-fa17232b3ec4.png">  

Add services to the active zones.  
* Run the commands that add services to the public zone, the web zone, the sales zone, and the mail zone.  
* public:  
Answer:  
$ sudo firewall-cmd --permanent --zone=public --add-service=http  
$ sudo firewall-cmd --permanent --zone=public --add-service=https  
$ sudo firewall-cmd --permanent --zone=public --add-service=pop3  
$ sudo firewall-cmd --permanent --zone=public --add-service=smtp  
<img width="482" alt="public" src="https://user-images.githubusercontent.com/106919343/200882600-167cec44-0912-4fdd-a2c9-b46dd5520a85.png">  

* web:  
Answer:  
$ sudo firewall-cmd --permanent --zone=web --add-service=http  
<img width="458" alt="web" src="https://user-images.githubusercontent.com/106919343/200882867-3c5fcb06-dae0-4b09-adae-3cca63dd9e20.png">  

* sales:  
Answer:  
$ sudo firewall-cmd --permanent --zone=sales --add-service=https  
<img width="499" alt="sales" src="https://user-images.githubusercontent.com/106919343/200883013-d0cf99b3-86c0-464f-b144-da9f9349b844.png">  

* mail:  
Answer:  
$ sudo firewall-cmd --permanent --zone=mail --add-service=smtp  
$ sudo firewall-cmd --permanent --zone=mail --add-service=pop3  
<img width="457" alt="mail" src="https://user-images.githubusercontent.com/106919343/200883137-688c8ec4-04b0-47ad-8cea-0287d46e7a5e.png">  

* What is the status of http, https, smtp and pop3?  
Answer:   
sudo firewall-cmd --zone=public --list-all  
sudo firewall-cmd --zone=web --list-all   
sudo firewall-cmd --zone=sales --list-all   
sudo firewall-cmd --zone=mail --list-all   
<img width="453" alt="public2" src="https://user-images.githubusercontent.com/106919343/200883485-1f1364ad-101f-4cf6-9c8d-9179abb8267b.png">  
<img width="448" alt="web2" src="https://user-images.githubusercontent.com/106919343/200883553-a8346341-c1bc-498f-8983-01da8144fc5b.png">  
<img width="449" alt="sales2" src="https://user-images.githubusercontent.com/106919343/200883593-3ce004c0-0ac7-49f9-866e-41d388ab8c0a.png">  
<img width="450" alt="mail2" src="https://user-images.githubusercontent.com/106919343/200883636-4ee837f6-b8f2-4f9c-967f-8e1e6eb2b88c.png">  

Add your adversaries to the drop zone.  
* Run the command that will add all current and any future blacklisted IPs to the drop zone.  
Answer:  
$ sudo firewall-cmd --permanent --zone=drop --add-source=10.208.56.23  
$ sudo firewall-cmd --permanent --zone=drop --add-source=135.95.103.76  
$ sudo firewall-cmd --permanent --zone=drop --add-source=76.34.169.118  
<img width="457" alt="drop" src="https://user-images.githubusercontent.com/106919343/200884336-91ffcaa8-afa4-4805-9719-ad2ca80ac4b6.png">  

Make rules permanent, then reload them.  

It's good practice to ensure that your firewalld installation remains nailed up and retains its services across reboots. This helps ensure that the network remains secure after unplanned outages such as power failures.  

*  Run the command that reloads the firewalld configurations and writes it to memory:  
Answer:  
$ sudo firewall-cmd --runtime-to-permanent  
sudo firewall-cmd --reload  
<img width="394" alt="saving" src="https://user-images.githubusercontent.com/106919343/200884907-a09436be-a381-4289-96a0-c7d0519f78df.png">  

View active zones.  
Now, provide truncated listings of all currently active zones. This is a good time to verify your zone settings.  

* Run the command that displays all zone services.  
Answer:  
$ sudo firewall-cmd --get-active-zones  
<img width="425" alt="active zones" src="https://user-images.githubusercontent.com/106919343/200885248-1851fab1-bd1c-4cdc-b055-488e613f01eb.png">  
 
Block an IP address.  

* Use a rich-rule that blocks the IP address 138.138.0.3 on your public zone.  
Answer:  
$ sudo firewall-cmd --zone=public --add-rich-rule=’rule family=”ipv4” source address=”138.138.0.3” reject’  
<img width="494" alt="rich rule" src="https://user-images.githubusercontent.com/106919343/200885412-2ddc7c6e-c5a8-49a7-abc7-ce47df8af0c5.png">  

Block ping/ICMP requests.  
Harden your network against ping scans by blocking icmp ehco replies.  

* Run the command that blocks pings and icmp requests in your public zone.  
Answer:  
$ sudo firewall-cmd --zone=public --add-icmp-block=echo-reply --add-icmp-block=echo-request  
<img width="481" alt="blocks" src="https://user-images.githubusercontent.com/106919343/200885615-6faf76e0-e763-4a55-ad27-9d48f832f793.png">  

Rule check.  
Now that you've set up your brand new firewalld installation, it's time to verify that all of the settings have taken effect.  

* Run the command that lists all of the rule settings. Do one command at a time for each zone.  
Answer:  
$ sudo firewall-cmd --zone=public --list-all  
$ sudo firewall-cmd --zone=sales --list-all  
$ sudo firewall-cmd --zone=mail --list-all  
$ sudo firewall-cmd --zone=web --list-all  
$ sudo firewall-cmd --zone=drop --list-all  

**Part 3: IDS, IPS, DiD and Firewalls**  

Now, you’ll work on another lab. Before you start, complete the following review questions.  

IDS vs. IPS Systems  

1. Name and define two ways an IDS connects to a network.  
Answer: Network tap: hardware device that provides access to the data flowing across a computer network  
  
   SPAN or port mirroring: sends a mirror image of all network data to another physical port, where packets can be captured and analyzed  

2. Describe how an IPS connects to a network.  
Answer: An IPS connects inline with the flow of data and is placed between the firewall and the network switch  

3. What type of IDS compares patterns of traffic to predefined signatures and is unable to detect zero-day attacks?  
Answer: Signature Based IDS  

4. What type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?  
Answer: Anomaly based IDS  
 
Defense in Depth  
1. For each of the following scenarios, provide the layer of defense in depth that applies:  

      a. A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.  

         Answer:  Physical and administrative   

      b. A zero-day goes undetected by antivirus software.  

         Answer:  Technical–software  

      c. A criminal successfully gains access to HR’s database.  

         Answer: Technical–network  

      d. A criminal hacker exploits a vulnerability within an operating system.  

         Answer: Technical–network  

      e. A hacktivist organization successfully performs a DDoS attack, taking down a government website.  

         Answer: Technical–network  

      f. Data is classified at the wrong classification level.  

         Answer: Administrative-policies, procedures, and awareness  

      g. A state-sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.  

         Answer: Technical–network  

2. Name one method of protecting data-at-rest from being readable on hard drive.  

   Answer: Encrypting hard drives  

3. Name one method of protecting data-in-transit.  

   Answer: Transmit data through an encryption platform that integrates with your existing systems  

4. What technology could provide law enforcement with the ability to track and recover a stolen laptop?  

   Answer: Through the installation of hardware or software that will help identify and locate the laptop.  This could be done through GPS tracking chips or monitoring software installed on the laptop.  

5. How could you prevent an attacker from booting a stolen laptop using an external hard drive?  

   Answer: Encrypting your hard drive  

Firewall Architectures and Methodologies  

1. Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.  

   Answer:  Circuit-level gateways  
   It is also done by stateful inspection firewalls, proxy firewalls, and next-generation firewalls  

2. Which type of firewall considers the connection as a whole? Meaning, instead of considering only individual packets, these firewalls consider whole streams of packets at one time.  

   Answer: Stateful inspection firewalls  

3. Which type of firewall intercepts all traffic prior to forwarding it to its final destination? In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it.  

   Answer: Proxy firewalls  

4. Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type—all without opening the packet to inspect its contents?  

   Answer: Packet filtering firewalls  

5. Which type of firewall filters solely based on source and destination MAC address?  

   Answer: MAC layer filtering firewall  

**Bonus Lab: “Green Eggs & SPAM”**  

In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker.  
 
* You will assume the role of a junior security administrator working for the Department of Technology for the State of California.  
 * As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high-priority alerts to senior incident handlers for further review.  
 * You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling threat intelligence as part of your incident report.  

Threat Intelligence Card   

Locate the indicator of attack in Sguil based off of the following:  

* Source IP/port: 188.124.9.56:80  
* Destination address/port: 192.168.3.35:1035  
* Event message: ET TROJAN JS/Nemucod.M.gen downloading EXE payload  

Answer the following questions:  

1. What was the indicator of an attack? (Hint: What do the details reveal?)   

   Answer: Msg: ET TROJAN JS/Nemucod.M.gen downloading EXE payload  
   downloads and runs additional malicious files on a system

2. What was the adversarial motivation (purpose of the attack)?  

   Answer: Info stealers--obtain personal information and more recently ransomware  

3. Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table:  

<img width="324" alt="table" src="https://user-images.githubusercontent.com/106919343/200889180-09e074f2-286d-449b-8464-d953355f40e2.png">  

4. What are your recommended mitigation strategies?  

   Answer: Using an intrusion detection system which will alert when there’s been an attempt to download a potential malware file.  As well as putting in place an      intrusion prevention system which will not only alert but respond to attacks.  

5. List your third-party references.  

https://www.f-secure.com/v-descs/trojan-downloader_js_nemucod.shtml  
https://www.cisecurity.org/insights/blog/malware-analysis-report-nemucod-ransomware  













