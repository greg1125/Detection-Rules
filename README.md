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
