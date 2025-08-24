# Day 2 – Brute Force Attack Detection (RDP)

## 🔹 Offensive Simulation (Attacker Side – Kali & PC)
- Created a custom password list (`pass.txt`) with weak passwords + correct VM password.
- Ran Hydra attack against RDP service of Azure VM (`98.70.40.100`):

  ```bash
  hydra -l labuser -P pass.txt -t 1 -W 3 rdp://98.70.40.100
Hydra generated multiple failed login attempts and eventually succeeded when it reached the correct password.

Observed ~7 4625 (failed logons) and ~3 4624 (successful logons) generated in Windows Security logs.

Also performed manual RDP login attempts from local PC to confirm additional failed logons.

## 🔹 Defensive Configuration (Azure Sentinel)
Verified logs in Log Analytics (SC200-WS) using:<img width="1916" height="917" alt="Screenshot 2025-08-24 145347" src="https://github.com/user-attachments/assets/98dd8f08-a31a-4ad7-910c-85dfc539af64" />
<img width="1916" height="911" alt="Screenshot 2025-08-24 145333" src="https://github.com/user-attachments/assets/09c33898-0eab-4b3a-b210-18fdd1817489" />
<img width="1917" height="907" alt="Screenshot 2025-08-24 145235" src="https://github.com/user-attachments/assets/6cd7ee8d-5602-4221-8ab9-55b67d10f51c" />
<img width="1913" height="916" alt="Screenshot 2025-08-24 142718" src="https://github.com/user-attachments/assets/2221bd9c-58f5-4494-95d1-09f4862e85e1" />
<img width="1909" height="907" alt="Screenshot 2025-08-24 142559" src="https://github.com/user-attachments/assets/3f7fa9c3-e582-49b1-8ac5-3146b1ed131a" />
<img width="656" height="760" alt="Screenshot 2025-08-24 141811" src="https://github.com/user-attachments/assets/e4981b9c-3f69-4abd-9b70-e6fd0bb04e3d" />


Event
| where EventLog == "Security" and EventID in (4625, 4624)
| project TimeGenerated, EventID, UserName
| order by TimeGenerated desc
| take 20
Confirmed presence of both failed (4625) and successful (4624) events.

## 🔹 Analytic Rule Created
Rule Name: Brute Force: Multiple Failed Logons

KQL Query:

Event
| where EventLog == "Security" and EventID == 4625
| summarize Failures = count() by UserName, bin(TimeGenerated, 10m)
| where Failures >= 5
Schedule: Run every 5 minutes, look back 10 minutes

Entity Mapping:

Account → Name → UserName

Incident Settings: Enabled “Create incidents from alerts”

## 🔹 Outcome
After generating 6–7 failed RDP logons within 10 minutes, the analytic rule was triggered.

Sentinel raised an Incident under SC200-WS → Incidents.

Incident contained:

UserName: labuser

Total Failures: ≥5

Timeline of failed logons

## 🔹 Observations
Hydra is noisy and easily detectable by Sentinel’s failed logon correlation.

Multiple failed attempts followed by a success clearly indicate brute-force behavior.

Detection worked as expected → alert raised in Sentinel.

## 🔹 Next Steps (Day 3 Plan)
Install IIS on the Azure VM to host a test web application.

Use Gobuster & Burp Suite for directory brute-force and vulnerability testing.

Build a Sentinel query/rule to detect web application scanning activity.

Document as Incident Report #2 (Web Attack).
