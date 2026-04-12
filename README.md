# **SOC Detection Engineering Lab**

---

## **Overview**

---

This project demonstrates a complete Security Operations Center (SOC) detection engineering workflow built within a controlled lab environment. The primary objective of this lab is to simulate real-world attacker behavior, generate relevant telemetry, and develop behavior-based detection rules using Elastic Security.

Rather than relying on static indicators or known signatures, detections in this lab are built around attacker techniques and observable patterns within system and authentication logs. Each detection is mapped to MITRE ATT&CK techniques and validated through controlled attack simulations.

This lab reflects how modern SOC environments operate, where detections are developed based on available telemetry, continuously tested, and integrated into an alerting and response pipeline.

---

## **Objectives**

---

The primary goal of this project is to build practical, real-world detection engineering skills.

This includes generating realistic attack activity, analyzing logs, creating detection rules, validating alerts, and integrating detections into a SOC workflow. A key focus is understanding how attackers behave across systems and how those behaviors can be identified through log data rather than relying on known signatures or static indicators.

---

## **Lab Environment**

---

The lab environment is built using a segmented virtual network to simulate enterprise infrastructure.

The environment consists of Windows endpoints, Linux endpoints, an attacker machine, and an Elastic Stack deployment used for centralized logging and detection. Elastic Agent is deployed across endpoints to collect telemetry such as Windows Event Logs and Linux authentication logs.

These logs are ingested into Elasticsearch and analyzed within Kibana using KQL and EQL-based detection rules. Attack simulations are performed using tools such as Impacket, Ncrack, and native system utilities to generate realistic adversary activity.

---

## **Detection Engineering Approach**

---

All detections in this lab follow a behavior-based methodology.

Instead of relying on specific tool names or static artifacts, detections are built around sequences of activity, abnormal thresholds, privilege changes, and authentication patterns that indicate malicious behavior. This approach ensures that detections remain effective even when attackers modify tools, randomize names, or change execution methods.

Each detection is designed based on the telemetry that is actually available in the lab environment, reflecting real-world constraints where visibility is often limited.

---

## **Detections Implemented**

---

## **Brute Force Authentication (SSH & RDP)**

---

## **Detection Rule**

---

```kql
/* SSH */
system.auth.ssh.event:"Failed" and user.name:*

/* RDP */
event.code:4625 and winlog.event_data.LogonType:"10"
```

---

## **Threshold Logic**

---

The detection is grouped by source IP address, username, and host name. An alert is triggered when five or more failed authentication attempts occur within a five minute window, indicating abnormal login behavior.

---

## **Description**

---

This detection identifies repeated failed authentication attempts within a short time window.

SSH brute force attempts are detected using Linux authentication logs, while RDP brute force attempts are identified using Windows Event ID 4625 with Logon Type 10.

A threshold-based approach highlights abnormal login behavior, where multiple failures from a single source indicate password guessing activity.

---

## **MITRE ATT&CK**

---

T1110 – Brute Force

---

## **PsExec Lateral Movement**

---

## **Detection Rule**

---

```eql
sequence by host.name with maxspan=5m
  [any where event.code == "4624" and winlog.logon.type == "3"]
  [any where event.code == "7045"]
```

---

## **Description**

---

This detection identifies lateral movement through service creation following remote authentication.

The rule correlates a successful network logon event with a subsequent service installation event. This sequence of activity is consistent with tools such as Impacket PsExec, even when service names and executables are randomized.

By focusing on behavioral patterns rather than static identifiers, this detection remains effective against modified attacker tooling.

---

## **MITRE ATT&CK**

---

T1021 – Remote Services  
T1569.002 – Service Execution  

---

## **Scheduled Task Persistence**

---

## **Detection Rule**

---

```kql
event.code:4698 and winlog.event_data.TaskName:*
```

---

## **Description**

---

This detection identifies persistence mechanisms through scheduled task creation.

It monitors Windows Event ID 4698, which indicates that a new scheduled task has been created. Where available, fields such as winlog.event_data.TaskName and winlog.event_data.TaskContent are used to analyze the command or executable associated with the task.

This detection was designed based on available telemetry within the lab environment, where process creation logs were not consistently available. As a result, the detection focuses on task creation events and their associated metadata.

---

## **MITRE ATT&CK**

---

T1053.005 – Scheduled Task/Job

---

## **Admin Group Privilege Escalation**

---

## **Detection Rule**

---

```eql
sequence by host.name with maxspan=5m
  [any where event.code == "4624" and winlog.logon.type == "3"]
  [any where event.code == "4732" and group.name == "Administrators"]
```

---

## **Description**

---

This detection identifies privilege escalation through modification of the local Administrators group.

It correlates a remote logon event with a subsequent group membership change, where a user is added to the Administrators group. This behavior is consistent with attackers leveraging valid credentials to gain elevated access.

The correlation-based approach improves detection fidelity by identifying meaningful sequences of activity rather than isolated events.

---

## **MITRE ATT&CK**

---

T1078 – Valid Accounts  
T1098 – Account Manipulation  

---

## **Detection Validation**

---

Each detection is validated through controlled attack simulations to ensure reliability and consistency.

Attack scenarios are executed multiple times using different variations to confirm that detections are not dependent on a single static value. Logs are reviewed within Elastic Security to verify that relevant events are generated and that alerts are consistently triggered.

```bash
# SSH brute force
ncrack -p 22 <target-ip>

# RDP brute force
ncrack -p 3389 <target-ip>

# Scheduled task persistence
schtasks /create /tn "Updater" /tr "C:\temp\malware.exe" /sc once /st 00:00

# Admin group escalation
net localgroup administrators user /add
```

Validation ensures that logs are generated correctly, detection rules trigger as expected, and alerts remain consistent across repeated testing scenarios.

---

## **Threat Simulation (Mythic C2)**

---

Adversary activity within this lab is simulated using the Mythic Command and Control (C2) framework.

Mythic is used to emulate post-exploitation behavior, allowing for realistic attacker techniques such as command execution, persistence, and lateral movement. The Apollo agent is deployed on a Windows endpoint to simulate an active compromise and generate telemetry.

This enables the lab to move beyond simple attack tools and instead replicate real-world adversary behavior, including stealthy execution and custom payload delivery.

The use of Mythic allows detections to be built against behavior rather than tool signatures, reinforcing a detection engineering approach focused on attacker techniques.

---

## **Mythic C2 Detection Considerations**

---

Detection logic for Mythic activity is based on process execution patterns and suspicious command behavior observed in Windows event logs.

Rather than relying on known filenames or hashes, detections focus on abnormal process creation, unusual command line arguments, and execution from non-standard directories.

This approach ensures that detection remains effective even when payloads are renamed or modified, which is common in real-world adversary activity.

---

## **MITRE ATT&CK Mapping**

---

T1059 – Command and Scripting Interpreter  
T1105 – Ingress Tool Transfer  
T1570 – Lateral Tool Transfer  

---

## **SOC Automation Pipeline**

---

Detections are integrated into an automated SOC workflow using Elasticsearch, n8n, Gmail, and osTicket.

Alerts generated in Elastic are written to a custom index. This index is continuously polled by an n8n workflow, which retrieves alert data, normalizes key fields, and formats the information into a structured alert.

The formatted alert is then sent via email to an osTicket instance, where it is automatically ingested and converted into a ticket. This creates a complete detection-to-response pipeline that simulates a real-world SOC environment.

This architecture is designed to operate within the Elastic free tier by avoiding webhook connectors and instead using index-based alerting.

---

## **Key Takeaways**

---

This project demonstrates that effective detection engineering is centered around understanding attacker behavior rather than identifying specific tools.

Behavior-based detections provide stronger coverage and remain resilient against evasion techniques such as tool modification and obfuscation. Building detections based on available telemetry is critical, as real-world environments often have limited visibility.

Integrating detections into a full SOC workflow ensures that alerts are actionable and contribute directly to incident response processes.

---

## **Future Improvements**

---

Future enhancements to this lab include expanding detection coverage to additional attack techniques, integrating cloud-based telemetry such as AWS CloudTrail and GuardDuty, and developing automated response capabilities.

Additional improvements will focus on increasing detection fidelity, reducing false positives, and creating structured investigation playbooks to support incident response.
