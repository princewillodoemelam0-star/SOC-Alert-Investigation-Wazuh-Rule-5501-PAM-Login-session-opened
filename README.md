# SOC-Alert-Investigation-Wazuh-Rule-5501-PAM-Login-session-opened
SOC investigation of Wazuh Rule 5501 (PAM: Login session opened). A step-by-step, plain-English walkthrough covering the agent, log analysis, MITRE ATT&amp;CK T1078, verdict, and prevention steps. By a junior SOC analyst open to remote L1 roles.


Analyst: Princewill Odoemelam (Prince), Junior SOC Analyst
Tools: Wazuh (SIEM/XDR), MITRE ATT&CK
Alert date: 2026-11-18
Severity: Level 3 (Low)
Verdict: Likely benign administrative activity (true positive for the detection, not an attack). Confirm with the change record or the account owner before closing.
1. TL;DR (for non-technical readers)
A user called ubuntu ran sudo on a Linux server and became root (the all-powerful admin account). Wazuh noticed and raised a low-severity alert.
That is a normal thing for admins to do. It only becomes a problem if the person was not supposed to do it, or if it happens at a strange time, in a strange pattern, or right after a suspicious login. This write-up shows how I checked, what I found, and how to keep this kind of activity under control.
2. What triggered the alert
Field
Value
Alert description
PAM: Login session opened.
Rule ID
5501
Rule level
3
Wazuh alert ID
1795013714.1201686
Timestamp (UTC)
2026-11-18T14:55:14.599Z
Rule fired times
22 (this rule has triggered 22 times, so it is common on this system)
Rule groups
pam, syslog, authentication_success
Plain English: PAM (Pluggable Authentication Modules) is the part of Linux that handles logins and privilege changes. Rule 5501 fires every time PAM records that a session was successfully opened. It is an "FYI" alert, not an "alarm" alert, which is why it is only level 3.
3. Step-by-step investigation
Step 1: Which machine is this?
Field
Value
Agent name
ip-10-60-2-97
Agent ID
000
Agent IP
Not populated (shown as "-")
Manager
ip-10-60-2-97
What I noticed:
Agent ID 000 is special in Wazuh. It is the Wazuh manager itself, not a remote endpoint. The agent name and the manager name are identical, which confirms it.
The hostname ip-10-60-2-97 follows the AWS naming style and points to a private address in the 10.x range, which means this is an internal cloud server, not something directly exposed to the internet.
Why this matters: the manager is the brain of the monitoring system. Any privileged activity on it deserves a closer look than on a regular workstation.
Step 2: Is there a source IP?
No. The agent IP field is empty, and the event data has no srcip field.
What that tells me: a remote login (SSH) would normally show an attacker or user IP address. Here there is none, because this was a local sudo command on the server itself, not a network login. That is the first sign this is likely someone already on the box (or a process running on it) rather than an outside connection.
Step 3: What does the raw log say?
Nov 18 14:55:12 ip-10-60-2-97 sudo[1139288]: pam_unix(sudo:session): session opened for user root(uid=0) by ubuntu(uid=1000)
Reading it piece by piece:
Part
Meaning
Nov 18 14:55:12
When the event happened on the server
ip-10-60-2-97
The server it happened on
sudo[1139288]
The program was sudo, running as process ID 1139288
pam_unix(sudo:session)
The PAM module that handled the session
session opened for user root(uid=0)
A session was opened with root privileges
by ubuntu(uid=1000)
The person or process asking for it was the user ubuntu
In one sentence: the ubuntu user used sudo to get root privileges on this server.
Step 4: Who are "ubuntu" and "root"?
From the decoded event data:
{
  "srcuser": "ubuntu",
  "uid": "1000",
  "dstuser": "root"
}
ubuntu (uid 1000) is the default first user on Ubuntu servers, and it is commonly the default admin account on AWS Ubuntu instances. UID 1000 means it is a regular (non-system) account.
root (uid 0) is the superuser, with full control of the system.
srcuser -> dstuser shows the direction of the privilege change: ubuntu -> root.
Step 5: How did Wazuh understand the log?
Field
Value
Meaning
Predecoder program
sudo
The first pass identified the program that wrote the log
Predecoder hostname
ip-10-60-2-97
Which host wrote it
Decoder
pam
The decoder that parsed the authentication details
Location
journald
The log came from the systemd journal on the server
Index
wazuh-alerts-4.x-2026.11.18
The daily index where the alert is stored
Input type
log
Collected as a normal log file/stream
Why this matters: the log came from the system's own journal, was parsed cleanly, and matches a known PAM format. Nothing looks malformed or tampered with. The alert was indexed about 2 seconds after the event (14:55:12 -> 14:55:14), which is normal pipeline delay.
Step 6: What does MITRE ATT&CK say?
Wazuh mapped this rule to:
Item
Value
Technique
T1078 - Valid Accounts
Tactics
Initial Access, Persistence, Privilege Escalation, Defense Evasion
Plain English:
MITRE ATT&CK is a public catalogue of how real attackers behave. T1078 describes attackers using legitimate, stolen, or abused accounts instead of breaking in with malware. Using a real account is attractive because it blends in with normal activity.
Important to understand: this mapping describes what an attacker could be doing with this behavior. It is not proof of an attack. The same log line is produced by every admin who legitimately runs sudo. The MITRE tags tell me why this event is worth a glance, not that something bad happened.
Step 7: Compliance tags on the rule
Wazuh also tags the rule with the compliance controls it helps satisfy:
Framework
Control
PCI DSS
10.2.5
HIPAA
164.312.b
TSC (SOC 2)
CC6.8, CC7.2, CC7.3
NIST 800-53
AU.14, AC.7
GDPR
IV_32.2
GPG13
7.8, 7.9
Why it matters: auditors want proof that privileged access is logged and monitored. This alert is exactly that evidence.
4. Analysis: benign or malicious?
Signs this is normal
Local sudo activity with no external source IP
ubuntu is the expected default admin account on this type of server
Clean, well-formed log and a standard PAM decoder match
Rule level is only 3, and the rule has fired 22 times, so it is a regular pattern, not a one-off spike
Single session-open event with no failed-login burst in this alert
What would make me escalate
The login right before the sudo came from an IP I do not recognize
Many failed attempts followed by a success (possible brute force)
sudo used at an unusual hour or by a user who normally never uses it
Root session followed by suspicious commands (new users, cron jobs, SSH key changes, disabled logging)
No matching change ticket or maintenance task
Checks I would complete before closing (pivoting in Wazuh)
Search for SSH logins to ip-10-60-2-97 shortly before 14:55 UTC on 2026-11-18 and check the source IP.
Look for failed authentication (rule group authentication_failed) for ubuntu in the hours before.
Review other 5501 alerts (all 22) and compare times: is 14:55 within the user's normal working pattern?
Look for follow-up activity: new user creation, /etc/sudoers edits, authorized_keys changes, service changes.
Ask the owner of the ubuntu account or check the change calendar: "Was someone doing maintenance on this server at 14:55 UTC?"
