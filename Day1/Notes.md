# Day 1 – Azure Setup & First Attack

## 🔹 VM Setup
- Created Azure Free Account.
- Created Resource Group: **SC200-Lab-RG**.
- Deployed Windows 10 Pro VM (**WinVM01**, size B2s).
- Configured Networking: Allowed RDP (3389).

## 🔹 Offensive Activity
- From Kali: ran Nmap scans on VM Public IP.
  ```bash
  nmap -A -Pn <VM_Public_IP>
Observed open ports (RDP, later HTTP/other services as enabled).

## 🔹 Defensive Setup
Created Log Analytics Workspace: SC200-WS.

Enabled Microsoft Sentinel on workspace.

Connected VM → Logs flowing into workspace.

Configured Data Collection Rule (SC200-DCR) to collect Windows Security Events.

Verified logs with query:

Event
| where EventLog == "Security"
| take 10
🔹 Observations
Successfully saw Security events in the Event table.

Failed logons (Event ID 4625) confirmed when testing wrong RDP logins.<img width="1917" height="919" alt="Screenshot 2025-08-23 191212" src="https://github.com/user-attachments/assets/92adeeaf-2115-4541-a4ca-8a30c33f7d60" />
<img width="1919" height="911" alt="Screenshot 2025-08-23 191146" src="https://github.com/user-attachments/assets/ad60ce08-49c6-439f-9f57-7a7c17ec8080" />
<img width="1912" height="931" alt="Screenshot 2025-08-23 180203" src="https://github.com/user-attachments/assets/82c9e7ce-035d-420a-b134-c8ec84d564dd" />
<img width="652" height="499" alt="Screenshot 2025-08-23 174933" src="https://github.com/user-attachments/assets/b51af5cf-9d98-442f-b8a0-853fe777ce10" />


🔹 Next Steps (Day 2)

Simulate brute-force attack using Hydra.

Detect failed logins (Event ID 4625 flood).

Create Sentinel Analytic Rule for brute-force detection.

Document results as Incident Report #1.
