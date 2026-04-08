---

## **PsExec / Impacket Lateral Movement Detection**

This detection focuses on identifying lateral movement activity performed through remote service execution over SMB. Lateral movement refers to an attacker moving from one machine to another within a network after initial access has already been obtained.

Tools such as PsExec and Impacket enable this behavior by allowing an attacker to authenticate to a remote system and execute commands without physically accessing the machine. These tools leverage SMB (Server Message Block), a Windows protocol used for file sharing and remote administration, to communicate with the target system.

The attack begins with a network-based authentication session, typically observed as a successful logon event (Event ID 4624 with Logon Type 3). In Windows logging, Event ID 4624 represents a successful login, while Logon Type 3 indicates that the login occurred over the network rather than locally. This distinction is important because remote execution techniques rely on network authentication to establish access.

Immediately following authentication, the attacker creates a service on the target system to execute commands. This activity is captured through Event ID 7045, which logs when a new service is installed. The combination of these two events, network authentication followed by service creation within a short time window, is a strong behavioral indicator of remote execution and lateral movement.

---

## **Detection Rule**

This detection is implemented using an Event Correlation rule within Kibana to identify a sequence of related events occurring on the same host.

```eql
sequence by host.name with maxspan=2m
  [authentication where event.code == "4624" and winlog.event_data.LogonType == "3"]
  [any where event.code == "7045" and winlog.event_data.ImagePath != null]

```

---

## **Detection Logic**

This detection is designed using a behavior-based approach rather than relying on static indicators.

A successful network logon (Event ID 4624 with Logon Type 3) indicates that a remote system authenticated to the target machine. This type of logon is commonly used in both administrative activity and attacker operations.

The creation of a service (Event ID 7045) indicates that code execution has been established on the system, often with elevated privileges. Remote execution tools commonly use this mechanism to run payloads.

When these two events occur in sequence within a short time window on the same host, it strongly suggests that a remote system authenticated and then executed code via service creation. This pattern is highly indicative of lateral movement. :contentReference[oaicite:0]{index=0}

Rather than asking whether a known service name such as `PSEXESVC` was used, this detection focuses on whether the behavioral sequence occurred. This makes the detection resilient to variations in tooling and attacker evasion techniques.

---

## **Why PSEXESVC Was Not Observed**

Traditional PsExec usage often results in the creation of a service named `PSEXESVC`, which is commonly used as a detection indicator.

However, during this lab, the observed service name was randomized and paired with a randomly generated executable path. This behavior is consistent with Impacket-based implementations, which dynamically generate service names and payload filenames to evade detection.

Because of this, detections that rely solely on static indicators such as known service names will fail. This highlights the limitation of signature-based detection and reinforces the need for behavior-based approaches.

---

## **MITRE Mapping**

This activity maps to the following MITRE ATT&CK technique:

T1021.002 – Remote Services: SMB / Windows Admin Shares

This technique describes the use of SMB and administrative shares to execute commands on remote systems, which aligns directly with how PsExec and Impacket operate.

---

## **Investigation Playbook**

When this alert is triggered, analysts should begin by identifying the source of the authentication. Determining the originating host or IP address helps establish whether the activity came from a known administrative system or an unexpected source.

Next, the user account involved in the authentication should be reviewed. Analysts should verify whether the account has administrative privileges and whether its usage aligns with expected behavior. Unexpected use of privileged accounts may indicate compromise.

The service creation event should then be analyzed. Particular attention should be given to the service name and executable path. Randomized service names or execution from unusual directories may indicate malicious activity.

The scope of the activity should be expanded by searching for similar events across other hosts. This helps determine whether the behavior is isolated or part of broader lateral movement.

Finally, analysts should determine whether the activity was authorized. If it cannot be attributed to legitimate administrative actions, the incident should be escalated for further investigation.

---

## **Sample Alert Output**

The following fields are typically observed in alerts generated from this detection:

```json id="2n8f4k"
{
  "host.name": "xxxxx",
  "user.name": "xxxx",
  "service.name": "vfpD",
  "@timestamp": "2026-04-07T19:44:07Z"
}
```
---

## **Screenshots**

The following evidence was captured to validate the detection and demonstrate how the attack appears across different stages of monitoring and response.

The detection rule within Kibana shows the EQL sequence used to correlate authentication and service creation events.

The successful network authentication event (Event ID 4624 with Logon Type 3) confirms that credentials were used to access the system remotely.

The service installation event (Event ID 7045) shows the creation of a new service with a randomized name and executable path, indicating remote execution.

The alert generated within Elastic Security confirms that the correlation rule successfully identified the activity.

The ticket generated within osTicket via the automated alert pipeline demonstrates a complete SOC workflow, where detection leads to incident creation and tracking.

![Detection Rule](kibana-rule.png)  
![Event 7045 Log](event-7045-log.png)

---

## **Key Insight**

Impacket-based lateral movement did not use the default `PSEXESVC` service name, instead generating randomized service names and executables. Detection was therefore designed around behavioral patterns rather than static indicators.

This reinforces the importance of behavior-based detection strategies in modern environments where attackers frequently modify tools to evade detection.

---

## **Operational Context**

This activity represents a high-confidence indicator of lateral movement within a Windows environment.

While legitimate administrative tools can create services, the combination of remote authentication followed immediately by service creation, especially with randomized naming, significantly increases the likelihood of malicious intent.

Analysts must evaluate the source of authentication, user context, and service execution details to determine whether the activity is authorized.

---

## **Key Takeaway**

This detection demonstrates how correlating multiple low-level system events can reveal higher-level attacker behavior.

By linking authentication activity with service creation, it is possible to identify lateral movement techniques that would otherwise evade single-event detections.

---
