## **Scheduled Task Persistence Detection**

---

This detection focuses on identifying persistence through the creation of Windows scheduled tasks. Scheduled tasks are a common technique used by attackers to maintain execution on a system after initial compromise.

Attackers can configure tasks to execute payloads at regular intervals or during specific triggers such as system startup or user logon. Because this technique does not require continuous attacker interaction, it is highly effective for maintaining long-term access.

In this lab environment, persistence was simulated by creating a scheduled task that executes `cmd.exe` every five minutes using the `schtasks` utility. The activity was performed both locally and remotely to demonstrate that scheduled task creation does not depend on a specific access method.

---

## **Detection Logic**

---

This detection is based on Windows Security Event ID 4698, which is generated when a scheduled task is created. Rather than relying on authentication context such as remote logons, the detection focuses on the behavior itself: the creation of a new scheduled task.

To improve detection fidelity, the rule evaluates both task naming patterns and task execution behavior. Suspicious task names often attempt to mimic legitimate system processes, while malicious tasks frequently execute command interpreters such as `cmd.exe` or `powershell.exe`.

This behavior-based approach ensures that both local and remote persistence mechanisms are detected, regardless of how the attacker initially accessed the system.

---

## **Detection Rule**

---

```kql
event.code:4698 AND (
  winlog.event_data.TaskContent:(*cmd.exe* OR *powershell.exe*)
  OR winlog.event_data.TaskName:("*update*" OR "*svc*" OR "*service*" OR "*system*" OR "*win*")
)
```
## **Field Notes**

---

This detection relies on the `winlog.event_data.TaskName` field to identify the created task and, when available, the `winlog.event_data.TaskContent` field to identify the command or executable associated with the task.

In this lab, process creation telemetry for `schtasks.exe` was not consistently available. Because of this, the detection was designed using the most reliable available telemetry: scheduled task creation events and their associated metadata.

This reflects a real-world detection engineering approach, where rules are built based on available data sources rather than assumed visibility.

---

## **Validation**

---

The detection was validated by creating scheduled tasks using the `schtasks` utility and confirming that the activity generated Event ID 4698 within Elastic Security.

Tasks were created using both obvious and disguised naming conventions to ensure that the detection logic was not dependent on a single static value. Additional validation was performed by recreating tasks to confirm that alerts were consistently triggered for new events.

The presence of the alert in Elastic Security confirms that the detection successfully identifies scheduled task persistence activity.

---

## **MITRE ATT&CK Mapping**

---

**T1053.005 – Scheduled Task**  
**Tactic:** Persistence  

---

## **Screenshots**

---

The following evidence was captured to validate the detection and demonstrate how scheduled task persistence appears across different stages of monitoring and response.

The command execution screenshot shows the creation of the scheduled task using the `schtasks` utility.

The Kibana Discover screenshot displays the generated Event ID 4698, confirming that the task creation was logged successfully.

The alert screenshot demonstrates that the detection rule triggered based on the scheduled task creation event.

The event details screenshot highlights key fields such as `winlog.event_data.TaskName` and task content, providing visibility into the persistence mechanism.


---

## **Key Insight**

---

Scheduled task creation is a strong indicator of persistence because it establishes recurring execution on a system without requiring further attacker interaction.

By focusing on task creation events and analyzing both naming patterns and execution behavior, this detection provides reliable coverage for both simple and advanced persistence techniques.

This reinforces the importance of behavior-based detection strategies, particularly in environments where process-level telemetry may be incomplete or inconsistent.
