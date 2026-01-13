# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JacobKingVA/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "jacob" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-13T16:49:22.3752993Z`. These events began at `2026-01-13T16:21:46.202058Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jacob-mde-test-"
| where FileName startswith "tor"
| where Timestamp >= datetime(2026-01-13T16:21:46.202058Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1605" height="410" alt="image" src="https://github.com/user-attachments/assets/58b07f35-24c4-43a8-9c61-44fe602a8064" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.4.exe". Based on the logs returned, at `2026-01-13T16:24:13.4442176Z`, an employee on the "jacob-mde-test-" device ran the file `tor-browser-windows-x86_64-portable-15.0.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "jacob-mde-test-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.4.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<img width="1376" height="127" alt="image" src="https://github.com/user-attachments/assets/af280f01-9bf6-4dfd-96cf-6aea274fab83" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "jacob" actually opened the TOR browser. There was evidence that they did open it at `2026-01-13T16:24:49.7945502Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| where Timestamp >= datetime(2026-01-13T16:21:46.202058Z)
| project  Timestamp, DeviceName, AccountName, ActionType, FolderPath, ProcessCommandLine, SHA256
```
<img width="1701" height="855" alt="image" src="https://github.com/user-attachments/assets/0b1fdcd5-2122-4237-99b7-56b731cc1a8c" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-01-13T16:27:44.0105777Z`, an employee on the "jacob-mde-test-" device successfully established a connection to the remote IP address `51.89.106.29` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\jacob\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were additional connections to sites over port `443` observed.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "jacob-mde-test-"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1622" height="396" alt="image" src="https://github.com/user-attachments/assets/da51fa30-9f3d-41ad-b6f0-2e3ceffc6154" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-01-13T16:21:46.202058Z`
- **Event:** The user "jacob" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\jacob\Downloads\tor-browser-windows-x86_64-portable-15.0.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-01-13T16:24:13.4442176Z`
- **Event:** The user "jacob" executed the file `tor-browser-windows-x86_64-portable-15.0.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.4.exe /S`
- **File Path:** `C:\Users\jacob\Downloads\tor-browser-windows-x86_64-portable-15.0.4.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-13T16:24:49.7945502Z`
- **Event:** User "jacob" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\jacob\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-13T16:27:44.0105777Z`
- **Event:** A network connection to IP `51.89.106.29` on port `9001` by user "jacob" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\jacob\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-01-13T16:27:00.9505259Z` - Connected to `64.65.1.33` on port `443`.
  - `2026-01-13T16:27:30.5289834Z` - Connected to `64.65.2.171` on port `443`.
  - `2026-01-13T16:27:44.1194753Z` - Connected to `84.240.60.234` on port `9001`.
  - `2026-01-13T16:27:45.350068Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "jacob" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-01-13T16:49:22.3752993Z`
- **Event:** The user "jacob" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\jacob\Desktop\tor-shopping-list.txt`

---

## Summary

The user "jacob" on the "jacob-mde-test-" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `jacob-mde-test` by the user `jacob`. The device was isolated, and the user's direct manager was notified.

---
