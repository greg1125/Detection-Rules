---

## **Mythic C2 Apollo Agent Detection**

This detection focuses on identifying command-and-control (C2) activity associated with the Mythic framework, specifically the Apollo agent. Command-and-control activity refers to communication between a compromised host and an attacker-controlled system used to issue commands, retrieve data, and maintain persistence.

The Mythic framework is a modern adversary simulation platform that allows attackers to deploy agents on compromised systems. The Apollo agent is a Windows-based payload that enables remote command execution, system enumeration, and persistence.

Unlike traditional malware, Mythic agents often operate using legitimate system processes and randomized artifacts, making them difficult to detect using signature-based methods. As a result, detection must focus on behavioral patterns and suspicious execution contexts.

This detection identifies execution of a known malicious binary associated with the Mythic Apollo agent within a user-accessible directory, which is highly unusual for legitimate software.

---

## **Detection Rule**

This detection is implemented using a KQL-based rule within Kibana to identify execution of a known malicious payload.

```kql
event.code:1 and 
winlog.event_data.Image:"C:\\Users\\Public\\Downloads\\windows-update.exe" or 
winlog.event_data.Hashes:*7356D8212E86361C50A1186C07FCB67A3497370273E96C9C742FF44938B1D5*
```
---

## **Detection Logic**

The rule identifies process execution events where a suspicious binary is launched from a public directory or matches a known malicious hash.

This detection is designed using a behavior-based and indicator-assisted approach.

Process execution events (Event ID 1) provide visibility into binaries being launched on a system. While process creation is common, execution from specific directories such as `C:\\Users\\Public\\Downloads` is highly unusual for legitimate system or enterprise software.

The use of a filename such as `windows-update.exe` is indicative of masquerading, where attackers attempt to disguise malicious binaries as legitimate system processes.

Additionally, the inclusion of a known file hash strengthens detection confidence by linking execution to a previously identified malicious payload.

By combining execution location, filename characteristics, and hash-based identification, this detection identifies likely C2 agent activity while minimizing false positives.

---

## **MITRE Mapping**

This activity maps to the following MITRE ATT&CK techniques:

T1071 – Application Layer Protocol (C2 Communication)  
T1105 – Ingress Tool Transfer  
T1036 – Masquerading  

These techniques describe how attackers establish communication channels, transfer payloads, and disguise malicious activity as legitimate processes.

---

## **Investigation Playbook**

When this alert is triggered, analysts should begin by reviewing the process execution details. This includes the process name, file path, and associated hash to confirm whether the binary is known or suspicious.

Next, the parent process should be analyzed to determine how the payload was launched. Suspicious parent processes or unexpected execution chains may indicate exploitation or user-assisted execution.

The affected host should be reviewed for additional signs of compromise, including other process executions, network connections, and persistence mechanisms.

Analysts should then check for outbound network activity associated with the process, as C2 agents typically communicate with external infrastructure.

Finally, the scope of the incident should be expanded to determine whether other hosts have executed the same binary or communicated with the same external systems.

---

## **Sample Alert Output**

```json
{
  "host.name": "LAB-SERVER-01",
  "user.name": "Administrator",
  "process.name": "windows-update.exe",
  "process.path": "C:\\Users\\Public\\Downloads\\windows-update.exe",
  "event.code": "1",
  "rule.name": "Mythic-C2-Apollo-Agent-Detected",
  "@timestamp": "2026-03-05T13:53:29Z"
}
```
---

## **Screenshots**

The following evidence was captured to validate the detection and demonstrate how the attack appears across different stages of monitoring and response.

The Mythic interface shows active callbacks, confirming that the Apollo agent successfully established a connection to the command-and-control server.

The detection rule within Kibana shows the KQL query used to identify execution of the malicious payload.

The alert generated within Elastic Security confirms that the rule successfully identified the activity and assigned a high severity score.

The host investigation view shows additional context about the affected system, including system details and related alert activity.

![Mythic C2 Interface](mythic-c2.png)  
![Detection Rule](mythic-rule.png)  
![Alert View](mythic-alert.png)

---

## **Key Insight**

The Mythic Apollo agent executed from a public directory using a masqueraded filename, allowing it to blend in with legitimate processes.

Detection was successful due to a combination of behavioral indicators and known malicious hash matching, demonstrating the effectiveness of layered detection strategies.

---

## **Operational Context**

This activity represents a high-confidence indicator of command-and-control activity.

Execution of a binary from a public directory combined with a suspicious filename and known malicious hash strongly indicates compromise. This behavior is not typical of legitimate enterprise software and aligns closely with attacker tradecraft.

Analysts should treat this activity as critical and initiate incident response procedures immediately.

---

## **Key Takeaway**

This detection demonstrates how combining behavioral analysis with known indicators can effectively identify modern C2 frameworks.

By focusing on execution context, file characteristics, and known malicious artifacts, it is possible to detect sophisticated attacker activity even when traditional signatures are bypassed.

---
