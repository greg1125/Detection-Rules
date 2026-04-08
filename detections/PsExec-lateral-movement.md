---

## **PsExec / Impacket Lateral Movement Detection**

This detection focuses on identifying lateral movement activity performed through remote service execution over SMB. Tools such as PsExec and Impacket enable an attacker to authenticate to a remote system and execute commands by creating a service on the target machine.

The attack works by first establishing a network-based authentication session, typically observed as a successful logon event (Event ID 4624 with Logon Type 3). This indicates that credentials were used to access the target system over the network.

Immediately following authentication, the attacker creates a service on the target system to execute commands. This activity is captured through Event ID 7045, which logs service installations. The combination of these two events within a short time window is a strong indicator of remote execution and lateral movement.

---

## **Why PSEXESVC Was Not Observed**

Traditional PsExec usage often results in the creation of a service named `PSEXESVC`. However, during this lab, the observed service name was randomized (e.g., `vfpD`) and paired with a randomly generated executable path.

This behavior is consistent with Impacket-based implementations of PsExec, which do not rely on fixed service names. Instead, they dynamically generate service names and payload filenames to reduce detection based on static indicators.

As a result, relying solely on the presence of `PSEXESVC` would fail to detect this activity. This highlights the limitations of signature-based detection approaches.

---

## **Behavior-Based Detection Approach**

To account for variations in tool behavior, detection logic was designed around the sequence of actions rather than specific indicators.

The detection identifies:

- A successful network logon (Event ID 4624, Logon Type 3)
- Followed by a service installation event (Event ID 7045)
- Occurring on the same host within a short time window

This approach ensures that detection remains effective regardless of the tool used or the specific service name generated.

By focusing on attacker behavior instead of static values, the detection is more resilient and applicable to real-world environments.

---

## **Detection Logic**

The following EQL rule was used to identify this activity:

```eql
sequence by host.id with maxspan=5m
  [any where event.code == "4624" and winlog.event_data.LogonType == "3"]
  [any where event.code == "7045"]
```

 **Screenshots**

The following evidence was captured to validate the detection.

Successful network authentication event (4624, Logon Type 3) demonstrates that credentials were used to access the target system over the network.

Service installation event (7045) shows the creation of a randomized service name and executable, indicating remote command execution behavior.

Detection alert triggered within Elastic Security confirms that the correlation rule successfully identified the attack sequence.

Ticket generated within osTicket via the automated alert pipeline demonstrates end-to-end SOC workflow from detection to incident response.

All screenshots are stored in the following directory.

---

## **Key Insight**

Impacket-based lateral movement did not use the default `PSEXESVC` service name, instead generating randomized service names and executables. Detection was therefore designed around behavioral patterns (remote authentication followed by service creation) rather than static indicators.

This reinforces the importance of behavior-based detection strategies when identifying adversary activity in modern environments.

---

## **Operational Context**

This activity represents a high-confidence indicator of lateral movement within a Windows environment. While administrative tools may exhibit similar behavior, the use of randomized service names and unexpected execution paths increases the likelihood of malicious intent.

Analysts should validate the source of authentication, including the originating IP address, the user account involved, the service name and executable path, and the frequency and timing of similar events across the environment.

---

## **Key Takeaway**

This detection demonstrates how correlating multiple low-level system events can reveal higher-level attacker behavior. By linking authentication activity with service creation, it is possible to identify lateral movement techniques that would otherwise evade simple, single-event detections.

---


