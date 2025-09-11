# Day 2 – Brute Force Attack Detection (RDP)

## 🔹 Offensive Simulation (Hydra)
- Ran Hydra against the Azure VM RDP service (`98.70.40.100`) using a custom wordlist:
  ```bash
  hydra -l labuser -P pass.txt -t 1 -W 3 rdp://98.70.40.100
Hydra generated multiple failed logon attempts and eventually succeeded with the correct password.

Outcome:

Event ID 4625 (failed logons) created in Windows Security logs.

Event ID 4624 (successful logon) created when the correct password was found.

Hydra Result Screenshot:
<img width="1287" height="733" alt="Screenshot 2025-09-11 112638" src="https://github.com/user-attachments/assets/53b4aa20-ca74-4b58-a404-bdd872b1b11b" />


🔹 Defensive Logs (Azure Sentinel / Log Analytics)
Query 1 – Verify Failed + Successful Logons
kusto
Copy code
Event
| where EventLog == "Security" and EventID in (4625, 4624)
| project TimeGenerated, EventID, UserName
| order by TimeGenerated desc
Confirmed multiple 4625 (failed) followed by 4624 (success) for labuser.

Screenshot:
<img width="1915" height="914" alt="Screenshot 2025-09-11 112425" src="https://github.com/user-attachments/assets/6e3f1521-1afa-4db3-b523-9f7156e5c93e" />


Query 2 – Brute Force Detection (≥5 fails in 10 minutes)
kusto
Copy code
Event
| where EventLog == "Security" and EventID == 4625
| summarize Failures = count() by UserName, bin(TimeGenerated, 10m)
| where Failures >= 5
Detected brute force against labuser with more than 5 failed attempts in a short time window.

Screenshot:
<img width="1913" height="912" alt="Screenshot 2025-09-11 112505" src="https://github.com/user-attachments/assets/2aa221f8-ecdc-4985-89a1-17e2fae1d5c8" />


🔹 Remediation
The account labuser was compromised.

Performed password reset on the VM to block attacker persistence.

🔹 Outcome
Successfully simulated and detected an RDP brute-force attack.

Verified in Sentinel logs using KQL queries.

Applied remediation by resetting the compromised account password.
