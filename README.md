## **🕵️ Data Exfiltration from Employee (PIP'd)** 

 

## 📖 Scenario:**  
An employee, John Doe, employed within a high-sensitivity department, was recently placed on a performance improvement plan (PIP) due to ongoing performance concerns. Following a series of behavioral red flags, management suspects that John may be preparing to exfiltrate proprietary data ahead of a potential departure from the organization. As a result, the security team has initiated an investigation focused on John’s assigned corporate device, maryanna-vm-mde, leveraging Microsoft Defender for Endpoint (MDE) to monitor for suspicious or unauthorized activity.
---

## 📈 Incident Summary and Findings**  

### **🗓️ Timeline Overview**  
1. **📁 Archiving Activity:**  
   - **Observed Behavior:** There was frequent creation of `.zip` files in a folder labeled "backup."  
   - **Detection Query (KQL):**  
     ```kql
     DeviceFileEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceNetworkEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceProcessEvents
     | top 20 by Timestamp desc
     ```
     ```kql
     DeviceFileEvents
     | where DeviceName == "maryanna-vm-mde"
     | where FileName endswith ".zip"
     | order by Timestamp desc
     ```
![image](https://github.com/user-attachments/assets/73961746-9fe4-4a0f-9a28-93c7df17b085)

     
2. **🧰 Process Analysis:**

   - **Observed Behavior:** I took one of the instances of a zip file being created, took the timestamp, and searched under DeviceProcessEvents for anything happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time, a PowerShell script silently installed 7zip and then used 7zip to zip up employee data into an archive.

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "maryanna-vm-mde";
     let specificTime = datetime(2025-04-29T15:18:24.6585829Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     | project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
     ```
![image](https://github.com/user-attachments/assets/2e7f70fd-98d9-4567-a943-5fb06d068923)


   3. **🌍 Network Exfiltration Check:**  
   - **Observed Behavior:** I searched around the same time for any evidence of exfiltration from the network, but I didn’t see any logs indicating such. 

   - **Detection Query (KQL):**  

     ```kql
     let VMName = "maryanna-vm-mde";
     let specificTime = datetime(2025-04-29T15:18:24.6585829Z);
     DeviceProcessEvents
     | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
     | where DeviceName == VMName
     | order by Timestamp desc
     ```  

4. **📨 Response:**  
   - I immediately isolated the system upon discovering the archiving activities relaying the information to the employee's manager, including everything with the archives being created at regular intervals via a PowerShell script. There didn’t appear to be any evidence of exfiltration. Standing by for further instructions from management.

---

---

## 🧱 MITRE ATT&CK Framework TTPs 

| **🎯 Tactic**       | **🛠️ Technique**                      | **🆔 ID** | **📄 Description**                                                                                                  |
| ------------------- | -------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------- |
| 💥 **Execution**    | PowerShell                             | T1059.001 | PowerShell scripts were used to silently install 7-Zip and compress data.                                           |
| 📦 **Collection**   | Archive Collected Data                 | T1560.001 | Sensitive data was compressed into `.zip` files using 7-Zip, likely to facilitate movement.                         |
| 🌐 **Exfiltration** | Exfiltration Over Alternative Protocol | T1048     | Although exfiltration wasn’t detected, this technique aligns with potential attempts to use non-standard protocols. |
| 🔎 **Discovery**    | Process Discovery                      | T1057     | Process inspection revealed suspicious behavior around data compression and 7-Zip execution.                        |

---

### 🧭 Next Steps  
1. Monitor John’s account for lateral movement or privilege escalation  
2. Deploy Data Loss Prevention (DLP) policies to alert on suspicious data handling. 
3. Escalate the incident for full forensic review and HR engagement.  

---

## 🧪 Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is communicating over the internet (ping test, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Confirm logs are actively collected (network, process, file events)
5. Run KQL queries in MDE advanced hunting to simulate detection

---
