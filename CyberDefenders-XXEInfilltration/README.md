# CyberDefenders Lab: XXE Infiltration Writeup

**Category:** Network Forensics | **Difficulty:** Easy | **Tactics:** Reconnaissance, Initial Access, Persistence, Privilege Escalation, Stealth, Credential Access, Discovery, Collection, Exfiltration | **Tools:** Wireshark, Brim

**Scenario:** An automated alert has detected unusual XML data being processed by the server, which suggests a potential XXE (XML External Entity) Injection attack. This raises concerns about the integrity of the company's customer data and internal systems, prompting an immediate investigation.

Analyze the provided PCAP file using the network analysis tools available to you. Your goal is to identify how the attacker gained access and what actions they took.

---

### Q1: During the attacker's port scan, what is the highest-numbered TCP port that responded as open on the victim host?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q1 - ](images/q1.png)
*   **Flag:** ``

---

### Q2: What's the complete URI of the PHP script vulnerable to XXE Injection?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q2 - ](images/q2.png)
*   **Flag:** ``

---

### Q3: What's the name of the first malicious XML file uploaded by the attacker?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q3 - ](images/q3.png)
*   **Flag:** ``

---

### Q4: What's the name of the web app configuration file the attacker read?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q4 - ](images/q4.png)
*   **Flag:** ``

---

### Q5: What is the password for the compromised database user?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q5 - ](images/q5.png)
*   **Flag:** ``

---

### Q6: Using the Wireshark filter `mysql.login_request`, what is the timestamp (UTC) of the attacker's first MySQL login attempt?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q6 - ](images/q6.png)
*   **Flag:** ``

---

### Q7: Can you identify the name of the web shell that the attacker uploaded for remote code execution and persistence?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q7 - ](images/q7.png)
*   **Flag:** ``
