---

## **PsExec / Impacket Lateral Movement Detection**

This detection focuses on identifying lateral movement activity performed through remote service execution over SMB. Lateral movement refers to an attacker moving from one machine to another within a network after initial access has already been obtained.

Tools such as PsExec and Impacket enable this behavior by allowing an attacker to authenticate to a remote system and execute commands without physically accessing the machine. These tools leverage SMB (Server Message Block), a Windows protocol used for file sharing and remote administration, to communicate with the target system.

The attack works by first establishing a network-based authentication session. This is typically observed as a successful logon event (Event ID 4624 with Logon Type 3). In Windows logging, Event ID 4624 represents a successful login, and Logon Type 3 specifically indicates that the login occurred over the network rather than locally at the machine. This is important because remote administration tools rely on network logins to function.

Immediately following authentication, the attacker creates a service on the target system to execute commands. A service in Windows is a background process that can run with elevated privileges and be started by the operating system. This activity is captured through Event ID 7045, which logs when a new service is installed.

The combination of these two events, network authentication followed by service creation within a short time window, is a strong behavioral indicator of remote execution and lateral movement.

---

## **Why PSEXESVC Was Not Observed**

Traditional PsExec usage often results in the creation of a service named `PSEXESVC`, which is commonly used as a detection indicator in many environments.

However, during this lab, the observed service name was randomized (e.g., `vfpD`) and paired with a randomly generated executable path (e.g., `%systemroot%\\wRDjalSy.exe`). This means there was no obvious or recognizable service name tied to PsExec.

This behavior is consistent with Impacket-based implementations of PsExec. Unlike the original Sysinternals PsExec tool, Impacket does not rely on fixed service names. Instead, it dynamically generates service names and payload filenames each time it runs. This is done intentionally to avoid detection methods that rely on static indicators such as known service names.

As a result, relying solely on the presence of `PSEXESVC` would fail to detect this activity. This demonstrates the limitations of signature-based detection, where detection depends on known values rather than behavior.

---

## **Behavior-Based Detection Approach**

To account for variations in tool behavior, detection logic was designed around the sequence of actions rather than specific indicators such as service names.

The detection identifies the following pattern:

- A successful network logon (Event ID 4624, Logon Type 3)
- Followed by a service installation event (Event ID 7045)
- Occurring on the same host within a short time window

Instead of asking "Was a known malicious service name used?", the detection asks "Did a remote login occur immediately before a service was created?"

This approach focuses on attacker behavior rather than tool-specific artifacts. Because of this, it remains effective even when attackers change tools, randomize names, or modify payloads.

By focusing on how the attack is performed rather than what it is called, the detection becomes more resilient and applicable to real-world environments.

---

## **Detection Logic**

The following EQL rule was used to identify this activity:

```eql
sequence by host.id with maxspan=5m
  [any where event.code == "4624" and winlog.event_data.LogonType == "3"]
  [any where event.code == "7045"]
```
---

## **Screenshots**

The following evidence was captured to validate the detection and demonstrate how the attack appears across different stages of monitoring and response within the SOC pipeline.

The successful network authentication event (Event ID 4624 with Logon Type 3) demonstrates that valid credentials were used to access the target system remotely. In Windows logging, Event ID 4624 represents a successful login, while Logon Type 3 specifically indicates a network-based logon rather than a local interactive login. This distinction is important because remote execution tools such as PsExec and Impacket rely on network authentication to establish access to a target machine.

The service installation event (Event ID 7045) shows the creation of a new service with a randomized name and executable path. In Windows, a service is a background process that can be executed with elevated privileges by the operating system. Tools like PsExec and Impacket commonly use this mechanism by uploading a payload and creating a temporary service to execute it. The presence of a randomly generated service name and executable path indicates an attempt to evade simple detection methods that rely on known service names such as `PSEXESVC`.

The detection alert triggered within Elastic Security confirms that the correlation rule successfully identified the sequence of events as suspicious. This demonstrates that combining multiple low-level events into a single detection rule allows for more accurate identification of attacker behavior.

The ticket generated within osTicket via the automated alert pipeline demonstrates a complete SOC workflow. Once the detection is triggered, the alert is processed through n8n, enriched if necessary, and converted into a structured incident ticket. This reflects how real-world SOC environments handle alerts by moving from detection to investigation and response.

All screenshots are stored in this directory 


---

## **Key Insight**

Impacket-based lateral movement did not use the default `PSEXESVC` service name, instead generating randomized service names and executables. Detection was therefore designed around behavioral patterns, specifically remote authentication followed by service creation, rather than static indicators.

This reinforces the importance of behavior-based detection strategies when identifying adversary activity in modern environments. Attackers frequently modify tools, randomize artifacts, and avoid known indicators, making static signature-based detection unreliable. By focusing on how an attack is performed rather than what it is called, detections become more resilient and effective.

---

## **Operational Context**

This activity represents a high-confidence indicator of lateral movement within a Windows environment. Lateral movement occurs when an attacker uses compromised credentials or access to move from one system to another within a network.

While legitimate administrative tools can also create services, the combination of remote authentication followed immediately by service creation, especially with randomized naming, significantly increases the likelihood of malicious intent. This pattern is uncommon in normal user behavior and aligns closely with known attacker techniques.

During investigation, analysts should validate several factors to determine whether the activity is legitimate or malicious. These include the source of authentication such as the originating IP address, the user account involved, the service name and executable path, and whether similar activity has occurred across other systems.

Understanding the full context of these events allows analysts to distinguish between authorized administrative actions and potential attacker behavior.

---

## **Key Takeaway**

This detection demonstrates how correlating multiple low-level system events can reveal higher-level attacker behavior. Individual events such as a successful login or a service installation may appear normal on their own, but when observed together in sequence, they provide strong evidence of lateral movement.

By linking authentication activity with service creation, it is possible to identify techniques used by attackers that would otherwise evade simple, single-event detections. This highlights the importance of event correlation and behavior-based detection in modern security operations.

---


