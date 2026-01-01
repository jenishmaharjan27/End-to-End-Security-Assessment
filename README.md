# End-to-End Security Assessment and Reporting Project

## Objective
The objective of this project was to perform a complete end-to-end cybersecurity assessment in a controlled lab environment. The project focused on identifying system and application vulnerabilities, exploiting them to understand real-world impact, and implementing mitigation strategies through secure configuration and coding practices. This hands-on assessment strengthened practical knowledge of offensive and defensive security techniques.

---

## Skills Learned
- Practical understanding of cybersecurity fundamentals and the CIA Triad
- Hands-on experience in reconnaissance and information gathering techniques
- Proficiency in vulnerability scanning and risk analysis using OpenVAS
- Experience in exploitation and penetration testing using Metasploit
- Understanding of password cracking techniques and credential security
- Secure coding and remediation of common web vulnerabilities (SQLi, XSS, CSRF)
- Ability to document findings and propose mitigation strategies
- Critical thinking in analyzing attack paths and security risks

---

## Tools Used
- **Kali Linux** – Attack and testing platform
- **OpenVAS** – Vulnerability scanning and risk assessment
- **Nmap** – Network scanning and service enumeration
- **Metasploit Framework** – Exploitation and penetration testing
- **John the Ripper** – Password hash cracking
- **DVWA (Damn Vulnerable Web Application)** – Web vulnerability testing
- **Whois / Nslookup / Shodan** – Passive reconnaissance tools

---

## Steps

### 1. Research and Documentation
Initial research was conducted on cybersecurity fundamentals, threat categories, ethical hacking methodologies, and legal guidelines. This phase established a strong theoretical foundation for the assessment.

*Ref 1: Cybersecurity Concepts and CIA Triad Documentation*

---

### 2. Reconnaissance and Information Gathering
Passive and active reconnaissance techniques were performed on the target website (<strong><em>vulnweb.com</em></strong>) to identify exposed services, infrastructure details, and potential attack surfaces.

- Passive reconnaissance using Whois, Nslookup, and Shodan
<img width="2560" height="1440" alt="Screenshot (298)" src="https://github.com/user-attachments/assets/0f3f0587-08ee-4177-9878-1d288fea6414" />
<p align="center">
  <em>Figure 2.1: Whois query results displaying domain registration and ownership details.</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (299)" src="https://github.com/user-attachments/assets/0235ed4a-4ff6-4514-906f-6ab1b38ebc1a" />
<p align="center">
  <em>Figure 2.2: Nslookup output showing DNS resolution and associated IP address information.</em>
</p>
<br>
<img width="2268" height="1301" alt="Screenshot 2025-12-24 201017" src="https://github.com/user-attachments/assets/8b47384f-efa1-4342-a023-9fd7da473b99" />
<p align="center">
  <em>Figure 2.3: Shodan search results revealing exposed services and infrastructure metadata.</em>
</p>
<br>

- Active reconnaissance using Nmap for port and service detection
<img width="2560" height="1440" alt="Screenshot (301)" src="https://github.com/user-attachments/assets/26af3dc0-fa62-4d83-aaec-1e2f0aff7ec8" />
<p align="center">
  <em>Figure 2.4: Nmap scan results identifying open ports and active services on the target system.</em>
</p>
<br>

---

### 3. Vulnerability Scanning
A full vulnerability scan was performed against the Metasploitable 2 system using OpenVAS. Critical vulnerabilities were identified and prioritized based on severity and exploitability.
- **Test Environment:** Kali Linux  
- **Test System:** Metasploitable 2  
- **Scanning Tool:** OpenVAS

<img width="2560" height="1440" alt="Screenshot (303)" src="https://github.com/user-attachments/assets/87e89781-84bc-4735-b95c-89d0b558e656" />
<p align="center">
  <em>Figure 3.1: OpenVAS Authentication Portal</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (304)" src="https://github.com/user-attachments/assets/92f132dc-a471-4f5f-9e1a-79d1141030fe" />
<p align="center">
  <em>Figure 3.2: Overview of the OpenVAS Web Dashboard</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (302)" src="https://github.com/user-attachments/assets/0be99fe7-1679-454b-bfde-9bc79b2fac26" />
<p align="center">
  <em>Figure 3.3: Verifying Connectivity with the Metasploitable 2 Instance</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (305)" src="https://github.com/user-attachments/assets/9ed22b30-da4e-4a72-923d-969ccf5f241e" />
<p align="center">
  <em>Figure 3.4: Configuring a New Scan Target Parameters</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (306)" src="https://github.com/user-attachments/assets/13dfc8d9-6645-4ed5-bfd5-39de4fd8c1e1" />
<p align="center">
  <em>Figure 3.5: Initializing a Vulnerability Scan Task for the Defined Target</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (307)" src="https://github.com/user-attachments/assets/7c63d3d5-dacb-4951-9bdd-26476d152416" />
<p align="center">
  <em>Figure 3.6: Confirmation of Completed Vulnerability Scan</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (309)" src="https://github.com/user-attachments/assets/c974a232-de33-4268-947f-54b56a1cf3d8" />
<p align="center">
  <em>Figure 3.7: Detailed Vulnerability Log and Findings Report</em>
</p>
<br>
The vulnerability scan identified several Critical (Severity 10.0) findings. While all high severity items require attention, they are prioritized below based on the Path of Least Resistance, an attacker would likely take within your LAN segment.
<br>
<img width="2560" height="1440" alt="Screenshot (310)" src="https://github.com/user-attachments/assets/71b86cd7-5ad6-4481-9218-2d4680f8c4a2" />
<p align="center">
  <em>Figure 3.8: Prioritizing Remediation based on Risk Scores</em>
</p>
<br>

---

### 4. Exploitation and Penetration Testing
A critical vulnerability in the vsftpd 2.3.4 service was exploited using the Metasploit Framework, resulting in successful root-level access to the target system. The identified vulnerability targeted is the vsftpd service on Port 21, which contains a malicious backdoor that triggers a root shell when a specific character sequence (a smiley face :)) is sent in the username.
- **Target Vulnerability:** vsftpd backdoor vulnerability
<br>
<img width="2560" height="1440" alt="Screenshot (311)" src="https://github.com/user-attachments/assets/02f16387-eed0-4473-955f-c3500fb864c3" />
<p align="center">
  <em>Figure 4.1: vsftpd Vulnerability Overiew</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (312)" src="https://github.com/user-attachments/assets/c5c56255-5b93-4996-9980-a1732b163a73" />
<p align="center">
  <em>Figure 4.2: Initialization of the Metasploit Framework (msfconsole)</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (313)" src="https://github.com/user-attachments/assets/cd57ce39-86c0-47cb-9b2f-b72e3b949477" />
<p align="center">
  <em>Figure 4.3: Identification and Selection of the Target Exploit Module</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (314)" src="https://github.com/user-attachments/assets/a987ae1f-10dd-45a8-8a1e-6937fc4a3878" />
<p align="center">
  <em>Figure 4.4: Configuration of the Remote Host (RHOST) Parameter</em>
</p>
<br>
<img width="2560" height="1440" alt="image" src="https://github.com/user-attachments/assets/a9db6b7f-c4a5-4dd2-a71d-df3987ea552c" />
<p align="center">
  <em>Figure 4.5: Execution of the Exploit Payload</em>
</p>
<br>
<img width="975" height="548" alt="image" src="https://github.com/user-attachments/assets/9c3371b8-e807-42bc-86d7-2c5e59ed7728" />
<p align="center">
  <em>Figure 4.6: Establishment of an Interactive Remote Shell</em>
</p>
<br>

---

### 5. Password Cracking
After gaining root access, password hashes were extracted from the `/etc/shadow` file and cracked using John the Ripper to demonstrate the risk of weak credentials.

*Ref 8: Extracted Password Hashes*  
*Ref 9: Cracked Password Results*

---

### 6. Secure Coding and Web Vulnerability Mitigation
DVWA was used to identify and exploit common web vulnerabilities, followed by secure code remediation.

- SQL Injection fixed using prepared statements
- Reflected XSS mitigated using output encoding
- CSRF prevented using anti-CSRF tokens

*Ref 10: SQL Injection Exploitation and Patch*  
*Ref 11: Reflected XSS Exploitation and Patch*  
*Ref 12: CSRF Attack and Mitigation*

---

## Results and Key Findings
- Multiple critical vulnerabilities were identified due to outdated services and misconfigurations
- Successful exploitation demonstrated real-world attack impact
- Weak password policies significantly increased compromise risk
- Secure coding practices effectively prevented common web attacks
- Defense-in-depth is essential for effective security posture

---

## Conclusion
This project demonstrated the full lifecycle of a cyber attack and its defense. It highlighted the importance of proactive security measures, secure coding practices, and continuous monitoring. The assessment reinforced that cybersecurity is an ongoing process requiring layered defenses, regular testing, and timely remediation.

---

## OpenVAS Report
🔗 https://drive.google.com/file/d/1FYFkRs9CBKNQpwUTWR9Iy3-H6OgCDjwl/view

---

## Disclaimer
All testing was conducted in a controlled lab environment for educational purposes only. No real-world systems were harmed.
