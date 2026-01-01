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
<br><br>
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
After gaining root access, password hashes were extracted from the `/etc/shadow` and `/etc/passwd` file and cracked using John the Ripper to demonstrate the risk of weak credentials.
<br><br>
<img width="2560" height="1440" alt="Screenshot (315)" src="https://github.com/user-attachments/assets/246b6d4c-2900-40c6-8384-81dd2692635e" />
<p align="center">
  <em>Figure 5.1: Unauthorized Access to the /etc/shadow File via Root Privileges</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (316)" src="https://github.com/user-attachments/assets/f37440d4-6fbc-43e1-9fd7-3a48dfbf2b69" />
<p align="center">
  <em>Figure 5.2: Secure Exfiltration of Password Hashes to the Local Attacker Machine</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (318)" src="https://github.com/user-attachments/assets/f8fd249e-3cc3-47c9-967c-1395189f1315" />
<p align="center">
  <em>Figure 5.3: Unshadowing and combining credentials into crackable format and Execution of a Brute-Force Attack using John the Ripper</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (320)" src="https://github.com/user-attachments/assets/cc7f41de-fe1a-4475-aee4-bdee7802b821" />
<p align="center">
  <em>Figure 5.4: Recovery of Plaintext Credentials from Cracked Hashes</em>
</p>
<br>

---

### 6. Secure Coding and Web Vulnerability Mitigation
DVWA was used to identify and exploit common web vulnerabilities, followed by secure code remediation.
<br><br>
<img width="2560" height="1440" alt="Screenshot (321)" src="https://github.com/user-attachments/assets/7eefaf9c-da86-49bf-b837-5039c9a4cd1e" />
<p align="center">
  <em>Figure 6.1: Verifying the Apache Web Server Operational Status</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (322)" src="https://github.com/user-attachments/assets/4786a221-8b70-478d-a068-7a32a495adbd" />
<p align="center">
  <em>Figure 6.2: Confirming Active MariaDB Database Services</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (323)" src="https://github.com/user-attachments/assets/b5c055b0-9f5e-4ac9-ac4c-60bfcef55d8d" />
<p align="center">
  <em>Figure 6.3: Initializing the Damn Vulnerable Web Application (DVWA) Dashboard</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (324)" src="https://github.com/user-attachments/assets/5a8740e0-1b72-408b-b91d-37613e11820b" />
<p align="center">
  <em>Figure 6.4: Adjusting Application Security Levels to "Low" for Vulnerability Testing</em>
</p>
<br>

- SQL Injection fixed using prepared statements
<img width="2560" height="1440" alt="Screenshot (326)" src="https://github.com/user-attachments/assets/526322f2-ef31-4ca1-8c92-09c3a433f487" />
<p align="center">
  <em>Figure 6.5: Successful SQL Injection via ' OR 1=1 # Payload to Bypass Authentication and Enumerate Database Records</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (328)" src="https://github.com/user-attachments/assets/715862a2-8164-44b3-965a-918d0a94f54d" />
<p align="center">
  <em>Figure 6.6: Source Code Analysis of the Insecure SQL Query Construction</em>
</p>
<br>
The database interpreted the '1'='1' statement as always true.
As a result, instead of returning a single user’s information, the application exposed the first name and surname of all users, including the administrator.
This is a classic case of authentication bypass and unauthorized data disclosure.

**Vulnerable Code:**

$id = $_REQUEST['id']; 

$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";

**Patching Procress**
1. Use placeholders instead of directly inserting user input:

    $stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');

2. Bind user input safely as a string:

    $stmt->bindParam(':id', $id, PDO::PARAM_STR);

3. Execute the query safely:

    $stmt->execute();

    $result = $stmt->fetchAll();



- Reflected XSS mitigated using output encoding
<img width="2560" height="1440" alt="Screenshot (329)" src="https://github.com/user-attachments/assets/36590e37-db4d-444d-822d-f15487c20ad8" />
<p align="center">
  <em>Figure 6.7: Identifying an Input Vector Reflecting Unsanitized Data into the HTML DOM</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (330)" src="https://github.com/user-attachments/assets/6d224c0d-fa71-4ba8-b22e-37993d97871f" />
<p align="center">
  <em>Figure 6.8: Execution of a Reflected XSS Payload Triggering an Unauthorized Browser Alert</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (331)" src="https://github.com/user-attachments/assets/2eb2932d-d02b-4823-9a08-434675496262" />
<p align="center">
  <em>Figure 6.9: Analysis of the Vulnerable Source Code Facilitating the XSS Attack</em>
</p>
<br>

- CSRF prevented using anti-CSRF tokens
<img width="2560" height="1440" alt="Screenshot (332)" src="https://github.com/user-attachments/assets/24a7f01d-826e-4af5-b357-3fb3a9347896" />
<p align="center">
  <em>Figure 6.10: Intercepting and Analyzing the HTTP GET Request for Password Modification</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (334)" src="https://github.com/user-attachments/assets/cdc0a09c-002f-46be-a6e4-88a55ca23829" />
<p align="center">
  <em>Figure 6.11: Examining URL Parameter Exposure During the Password Change Process</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (335)" src="https://github.com/user-attachments/assets/16cc1cf2-a6fc-4977-b471-9495b2994835" />
<img width="2560" height="1440" alt="Screenshot (336)" src="https://github.com/user-attachments/assets/c641e169-cb8e-4ad4-a643-7fef75e98259" />
<p align="center">
  <em>Figure 6.12: Execution of a Malicious CSRF Payload Within the Victim’s Browser Context</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (337)" src="https://github.com/user-attachments/assets/f48d0b73-c8db-4f69-a105-c295bd696d5b" />
<p align="center">
  <em>Figure 6.13: Verification of Unauthorized Password Change via CSRF Exploitation</em>
</p>
<br>
<img width="2560" height="1440" alt="Screenshot (338)" src="https://github.com/user-attachments/assets/1a8ee3ca-cf59-4407-9609-3db453141b02" />
<p align="center">
  <em>Figure 6.14: Source Code Review of the Insecure Password Update Functionality</em>
</p>
<br>

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
