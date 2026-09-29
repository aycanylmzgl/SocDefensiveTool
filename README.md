# SOC Defensive Tool - Event Log Hunter

A lightweight, real-time threat hunting tool developed in C# to monitor Windows Security Logs and detect potential brute-force attacks.

## Project Overview
In Enterprise SOC (Security Operations Center) environments, detecting unauthorized access attempts swiftly is critical. This console-based defensive tool hooks directly into the Windows Event Log API to monitor the "Security" channel in real-time. It specifically hunts for **Event ID 4625 (Failed Logon)** and parses the raw log data to extract actionable threat intelligence.

## Key Features
* **Real-Time Monitoring:** Uses event-driven architecture (`EnableRaisingEvents`) instead of resource-heavy loops to capture logs the exact millisecond they are generated.
* **Payload Parsing:** Automatically parses the Windows Event parameter strings to extract the **Target User** (Index 5) and the **Source IP Address** (Index 19).
* **Alerting:** Generates immediate visual alerts in the console for Blue Team analysts to review.

## Technologies Used
* **Language:** C# (.NET 10.0)
* **Libraries:** `System.Diagnostics.EventLog`
* **Concepts:** Threat Hunting, Log Parsing, SIEM Logic, Windows Internals.

## 🚀 How to Run
1. Clone the repository to your local Windows machine.
2. Open the solution in Visual Studio.
3. **Important:** Restart Visual Studio as an **Administrator**. Reading Windows Security Logs requires elevated privileges.
4. Build and Run the application. 
5. To test, open an administrative command prompt and run a dummy logon attempt: `runas /user:FakeHacker cmd`
