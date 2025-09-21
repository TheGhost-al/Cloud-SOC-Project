### Day 3 – Port-scan detection (Windows Filtering Platform / SC200-WS)

## 🔹 Goal
Simulate port-scan / connection flood against **WinVM01 (98.70.40.100)** on **port 8080**, verify Windows Filtering Platform events (EventID **5156**) are ingested into the `SC200-WS` workspace, and create a KQL detection query.

---

## 🔹 Environment
- VM: **WinVM01** (Windows 10 Pro) — Public IP: **98.70.40.100**, user: `labuser`  
- Resource Group: `SC200-Lab-RG`  
- Log Analytics Workspace: `SC200-WS`  
- Data Collection Rule: `SC200-DCR` (Security events)  
- Azure Monitor Agent: installed and reporting

---

## 🔹 Actions (commands & verification)

### 1) Start HTTP listener on WinVM01 (PowerShell)
```powershell
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add('http://+:8080/')
$listener.Start()
Write-Host "Listening on port 8080..."
````

* Screenshot: `Day3_screenshots/01_vm_listener.png`
<img width="982" height="1020" alt="Screenshot 2025-09-21 195623" src="https://github.com/user-attachments/assets/9099ca09-22ef-489c-ae4b-c0453baa402f" />

---

### 2) Allow inbound in Windows Firewall (PowerShell)

```powershell
New-NetFirewallRule -DisplayName "Allow-8080" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
New-NetFirewallRule -DisplayName "Allow-8000-8010" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000-8010
Get-NetFirewallRule -DisplayName "Allow-8080","Allow-8000-8010" | Format-Table DisplayName,Enabled,Profile
```

* Screenshot: `Day3_screenshots/02_vm_firewall.png`
<img width="972" height="351" alt="Screenshot 2025-09-21 195842" src="https://github.com/user-attachments/assets/ad3f3f1c-ad43-4305-8ef0-df2f22f73f11" />

---

### 3) Confirm DCR collects Filtering Platform events (Cloud Shell)

```bash
az monitor data-collection rule show --name SC200-DCR --resource-group SC200-Lab-RG --query "dataSources" -o json
# Ensure xPathQueries includes EventID 5156/5157
```

* Screenshot: `Day3_screenshots/03_dcr_updated.png`
<img width="933" height="461" alt="Screenshot 2025-09-21 200106" src="https://github.com/user-attachments/assets/1f65bffb-6605-4363-9d31-c7a9a6284fe6" />

---

### 4) From attacker (Kali): scan to generate connections

```bash
# scan around 8080 and generate volume to 8080
nmap -sT -Pn -T4 -p 8080,8081-8100 98.70.40.100
for i in {1..30}; do curl -sS http://98.70.40.100:8080/ >/dev/null; done
```

* Screenshot: `Day3_screenshots/04_kali_scan.png`
<img width="969" height="920" alt="Screenshot 2025-09-21 200303" src="https://github.com/user-attachments/assets/4a31c7d9-0390-479d-a01e-46d678d5e06c" />

---

### 5) Verify raw 5156 events in Log Analytics (KQL)

```kql
SecurityEvent
| where TimeGenerated >= ago(15m) and EventID == 5156
| extend ed = tostring(EventData)
| where ed contains "DestPort" and ed contains "8080"
| extend srcIP = extract(@"SourceAddress.*?>([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)<", 1, ed),
         dstPort = extract(@"DestPort.*?>(\d+)<", 1, ed)
| project TimeGenerated, Computer, srcIP, dstPort
| sort by TimeGenerated desc
| take 20
```

* Screenshot: `Day3_screenshots/05_sentinel_5156.png`
<img width="1902" height="908" alt="Screenshot 2025-09-21 200537" src="https://github.com/user-attachments/assets/950a9e91-cc54-48e0-ba0e-fd8cc5b357fa" />

---

### 6) Detection query (summarize repeated attempts from external IPs)

```kql
SecurityEvent
| where TimeGenerated >= ago(15m) and EventID == 5156
| extend ed=tostring(EventData)
| extend srcIP=extract(@"SourceAddress.*?>([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)<",1,ed)
| where isnotempty(srcIP) and not(srcIP startswith "10.") and not(srcIP startswith "172.") and not(srcIP startswith "192.168") and srcIP!="127.0.0.1"
| summarize Attempts=count() by srcIP, bin(TimeGenerated,5m)
| where Attempts > 8
| order by Attempts desc
```

* Screenshot: `Day3_screenshots/06_detection_results.png`
<img width="1915" height="898" alt="Screenshot 2025-09-21 200637" src="https://github.com/user-attachments/assets/a8a88313-f6c8-4093-ba84-ec58dd325000" />

---

## 🔹 Results & observations

* Windows recorded local **5156** events (confirmed with `Get-WinEvent` on the VM).
* `SC200-DCR` updated to include EventIDs **5156 / 5157** and events are ingested into `SC200-WS`.
* Sentinel Logs show external attacker IP(s) (example: `49.43.200.170`) connecting to **DestPort=8080**.
* The detection KQL surfaced repeated connection attempts after running a curl loop from Kali.

---

## 🔹 Tuning & next steps

* Threshold used in lab: `Attempts > 8` (intentionally low for testing). In production, profile baseline traffic and tune thresholds.
* Next: create a scheduled analytic rule (or a Defender scheduled query rule) using the detection KQL and optionally add a playbook to block the attacker (NSG or Firewall) automatically. (For this project we document detection only — automation optional.)

---

## 🔹 How to reproduce quickly

1. Start listener on WinVM01 (`http://+:8080/`).
2. Ensure DCR includes 5156/5157 and the VM is sending Security events to `SC200-WS`.
3. From attacker host, generate repeated requests: `for i in {1..30}; do curl -sS http://98.70.40.100:8080/ >/dev/null; done`.
4. Run the detection KQL and capture screenshots.

