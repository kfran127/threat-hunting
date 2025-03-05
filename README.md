
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

## Overview
This project involves a **threat hunt investigation** focused on detecting unauthorized usage of the **TOR browser** within a corporate network. The goal is to identify suspicious activity, analyze potential security risks, and generate a detailed report.

### **Scenario**
Management suspects that some employees may be using the **TOR browser** to bypass network security controls. **Recent network logs** indicate unusual encrypted traffic patterns and connections to **known TOR entry nodes**. Additionally, anonymous reports suggest that employees are discussing ways to access restricted sites during work hours.

📂 [Scenario Creation](#)

### **Objective**
- Detect **unauthorized TOR usage**
- Identify **Indicators of Compromise (IoCs)**
- Document findings and notify management if TOR usage is confirmed

---

## 🛠 Technology Utilized
- **Windows 10 Virtual Machines** (Microsoft Azure)
- **EDR Platform:** Microsoft Defender for Endpoint
- **Kusto Query Language (KQL)**
- **Tor Browser**

---

## 📑 Table of Contents
1. [TOR-Related IoC Discovery Plan](#tor-related-ioc-discovery-plan)
2. [Threat Hunting Steps](#threat-hunting-steps)
   - [Device File Events](#1-searched-the-devicefileevents-table)
   - [Device Process Events](#2-searched-the-deviceprocessevents-table)
   - [Process Execution Tracking](#3-searched-the-deviceprocessevents-table-for-tor-browser-execution)
   - [Network Traffic Analysis](#4-searched-the-devicenetworkevents-table-for-tor-network-connections)
3. [Chronological Event Timeline](#chronological-event-timeline)
4. [Summary & Response](#summary--response)

---

## 🔎 TOR-Related IoC Discovery Plan
To detect unauthorized TOR usage, the following approach was taken:
- **Check `DeviceFileEvents`** for file creation related to `tor.exe`, `firefox.exe`, or TOR installation packages.
- **Check `DeviceProcessEvents`** for signs of TOR browser execution.
- **Check `DeviceNetworkEvents`** for outgoing TOR connections over known ports.

---

## 🔍 Threat Hunting Steps

### 1️⃣ Searched the `DeviceFileEvents` Table
**Findings:**
- **User:** `employee`
- **Event:** Downloaded a TOR installer and created TOR-related files on the desktop.
- **Time:** `2024-11-08T22:14:48.6065231Z`

📜 **Query Used:**
```kql
DeviceFileEvents  
| where FileName contains "tor"  
| where InitiatingProcessAccountName == "employee"  
| project Timestamp, FileName, FolderPath, SHA256
```

---

### 2️⃣ Searched the `DeviceProcessEvents` Table
**Findings:**
- **Event:** Employee executed `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder.
- **Time:** `2024-11-08T22:16:47.4484567Z`

📜 **Query Used:**
```kql
DeviceProcessEvents  
| where ProcessCommandLine contains "tor-browser"  
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### 3️⃣ Searched the `DeviceProcessEvents` Table for TOR Browser Execution
**Findings:**
- **Event:** User launched `tor.exe`, confirming active TOR browser use.
- **Time:** `2024-11-08T22:17:21.6357935Z`

📜 **Query Used:**
```kql
DeviceProcessEvents  
| where FileName has_any ("tor.exe", "firefox.exe")  
| project Timestamp, AccountName, FileName, FolderPath
```

---

### 4️⃣ Searched the `DeviceNetworkEvents` Table for TOR Network Connections
**Findings:**
- **Event:** Employee connected to `176.198.159.33` over port `9001`.
- **Time:** `2024-11-08T22:18:01.1246358Z`

📜 **Query Used:**
```kql
DeviceNetworkEvents  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9050", "9150", "443")  
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName
```

---

## 📊 Chronological Event Timeline

| Timestamp  | Event | Details  |
|------------|-------|----------|
| `22:14:48` | 📥 File Download | Employee downloaded `tor-browser-windows-x86_64-portable-14.0.1.exe`  |
| `22:16:47` | 🖥 Process Execution | User ran TOR installer in silent mode  |
| `22:17:21` | 🚀 TOR Browser Launch | `tor.exe` executed, confirming TOR browser use  |
| `22:18:01` | 🌍 Network Connection | Connected to `176.198.159.33` on port `9001`  |

---

## 🛑 Summary & Response
The user `employee` installed and actively used the **TOR browser**, establishing network connections to known **TOR entry nodes**. Based on these findings, the following actions were taken:

✅ **Immediate Response:**
- **The device was isolated** to prevent further TOR activity.
- **Management was notified** of unauthorized TOR usage.
- **User’s direct manager was informed** for further disciplinary review.

✅ **Future Mitigation Strategies:**
- **Implement firewall rules** to block TOR entry node connections.
- **Monitor user activity logs** for any signs of unauthorized browsing.
- **Conduct employee security awareness training** on acceptable internet use.

---

## 🔗 Connect With Me
📌 [**LinkedIn - Kency Francois**](https://linkedin.com/in/kency-francois)  

🚀 **Thank you for reviewing this project!** If you're interested in more cybersecurity projects, check out my GitHub profile!
