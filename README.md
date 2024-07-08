# Table of Contents

1. [Introduction](#introduction)
2. [Note](#note)
3. [Justification for Additional Privileges](#justification-for-additional-privileges)
    - [_SeTakeOwnershipPrivilege_](#setakeownershipprivilege)
    - [_SeLoadDriverPrivilege_](#seloaddriverprivilege)
    - [_SeBackupPrivilege_](#sebackupprivilege)
    - [_SeRestorePrivilege_](#serestoreprivilege)
4. [Capabilities and Impact](#capabilities-and-impact)
5. [Proof of Concept](#proof-of-concept)
    - [Step 1: Initial User Context](#step-1---initial-user-context)
    - [Step 2: Running WannaBeTrusted](#step-2---running-wannabetrusted)
    - [Step 3: Identifying TrustedInstaller Process](#step-3---identifying-trustedinstaller-process)
    - [Step 4: Identifying Winlogon Processes](#step-4---identifying-winlogon-processes)
    - [Step 5: Checking Enabled Privileges](#step-5---checking-enabled-privileges)
    - [Step 6: Post-Escalation User Context](#step-6---post-escalation-user-context)
6. [Detailed Workflow](#detailed-workflow)
7. [Prerequisites](#prerequisites)
8. [Usage](#usage)
9. [Disclaimer](#disclaimer)

# Introduction

WannaBeTrusted is a Windows utility engineered for leveraging privilege escalation by duplicating tokens from highly privileged processes to obtain SYSTEM and TrustedInstaller privileges.

## Note

This code enables four privileges. However, users are free to customize this code for enabling other privileges by modifying the corresponding lines of the code. The list of privileges is accessible through [Microsoft Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment).

## Justification for Additional Privileges

- _SeTakeOwnershipPrivilege_: This privilege allows the user to take ownership of objects (files, folders, registry keys) on the system. Once ownership is taken, the user can modify the DACL to grant themselves full control. This is particularly useful for altering or deleting critical system files and settings to achieve privilege escalation or maintain persistence;
  
- _SeLoadDriverPrivilege_: With this privilege, the user can load and unload device drivers using functions such as _NtLoadDriver_ and _NtUnloadDriver_. Malicious drivers operating at the kernel level can intercept and manipulate kernel-mode operations, allowing advanced persistence techniques and evasion of security controls;
  
- _SeBackupPrivilege_: This privilege allows the user to bypass file and directory permissions using backup APIs such as _BackupRead_ and _BackupWrite_. By accessing these APIs, a user can read and write files without adhering to the standard security checks, enabling the extraction of sensitive information such as password hashes from the SAM database or critical configuration files;
  
- _SeRestorePrivilege_: Similar to the backup privilege, this privilege allows the user to bypass file and directory permissions to restore system files. By using APIs like _RestoreFile_ and manipulating the VSS, a user can replace protected system files with malicious versions or restore previously backed-up files to maintain persistence;
  
By enabling these privileges, testers can simulate advanced attack techniques. 

## Capabilities and Impact

- Impersonating SYSTEM and TrustedInstaller accounts grants an attacker unparalleled control over a Windows system. With SYSTEM privileges, the attacker can install and manipulate **kernel-mode drivers** (_SeLoadDriverPrivilege_), allowing the deployment of rootkits. A rootkit can operate with kernel-level access, providing an undetectable backdoor by intercepting and modifying system calls to conceal malicious activities from most security tools;

- **Code injection** into highly privileged processes is another critical capability enabled by SYSTEM or TrustedInstaller privileges. Regular administrators are typically restricted from accessing the memory of processes running at higher privilege levels. By injecting code into processes like lsass.exe or winlogon.exe, an attacker can execute arbitrary code with elevated privileges, facilitating actions such as credential theft or further privilege escalation;

- **Disabling or bypassing security solutions** is also significant. SYSTEM privileges allow an attacker to terminate or modify security processes that lower-privileged accounts cannot tamper with. For instance, an attacker could modify Windows Defender settings to exclude critical directories from scanning, or they could use SYSTEM privileges to stop security services entirely, rendering the system defenseless. Even with an EDR system in place, elevated privileges enable an attacker to tamper with or disable EDR components. SYSTEM or TrustedInstaller privileges allow actions like unloading EDR drivers, modifying EDR configurations, or unhooking and deleting EDR-related files, effectively blinding the EDR and preventing it from detecting or responding to malicious activities.

**However, it is crucial to note that the practical success of these techniques may be constrained by modern EDR solutions. These solutions utilize advanced heuristics, behavioral analysis, and real-time monitoring of kernel-mode activities to detect and thwart unauthorized actions, thereby providing robust protection against such privilege escalation and deployment of rootkit attempts.**

## Proof of Concept

The following images demonstrate the functionality of WannaBeTrusted in a practical scenario. Each step is documented to provide a clear understanding of the processes involved and the results achieved.

**Step 1 - Initial User Context**

The initial user context is shown with the _whoami /all_ command, displaying the user's SID, group memberships, and privilege levels. This information is crucial to establish the baseline from which WannaBeTrusted will escalate privileges. The user is part of the "Administrators" group, but this user is currently operating at a medium mandatory level:

<div align="center">
  <a href="https://github.com/lucademers/WannaBeTrusted/assets/168311527/00fc2300-6c43-4604-8724-b313151ed3f8">
    <img src="https://github.com/lucademers/WannaBeTrusted/assets/168311527/00fc2300-6c43-4604-8724-b313151ed3f8" alt="Initial User Context" width="600"/>
  </a>
  <p><em><strong>Figure 1 </strong> - Initial user context showing current privileges and group memberships</em></p>
</div>

### **Step 2 - Running WannaBeTrusted**

The execution of the WannaBeTrusted tool is shown, detailing the steps taken to impersonate the _winlogon.exe_ process and subsequently the TrustedInstaller process. The tool successfully duplicates the tokens and enables necessary privileges, culminating in the creation of a process running with TrustedInstaller and SYSTEM privileges:

<div align="center">
  <a href="https://github.com/lucademers/WannaBeTrusted/assets/168311527/9ef14cd3-eeee-4881-ba59-5b80d4d649c2">
    <img src="https://github.com/lucademers/WannaBeTrusted/assets/168311527/9ef14cd3-eeee-4881-ba59-5b80d4d649c2" alt="Running WannaBeTrusted" width="600"/>
  </a>
  <p><em><strong>Figure 2</strong> - Steps to impersonate highly privileged processes</em></p>
</div>

### **Step 3 - Identifying TrustedInstaller Process**

Using Process Hacker, the TrustedInstaller.exe process is identified with **PID 7056**. This process, running with high privileges, is a target for token duplication to obtain TrustedInstaller privileges. This step is essential to confirm that the TrustedInstaller service is active and its process can be leveraged:

<div align="center">
  <a href="https://github.com/lucademers/WannaBeTrusted/assets/168311527/9a54fc43-ba56-453e-a5a5-424d9c97caaf">
    <img src="https://github.com/lucademers/WannaBeTrusted/assets/168311527/9a54fc43-ba56-453e-a5a5-424d9c97caaf" alt="Identifying TrustedInstaller Process" width="600"/>
  </a>
  <p><em><strong>Figure 3</strong> - TrustedInstaller process with PID 7056</em></p>
</div>

### **Step 4 - Identifying Winlogon Processes**

The winlogon.exe processes are identified, with **PIDs 580** and 3540. These processes run with SYSTEM privileges and are critical targets for the initial privilege escalation step. The ability to duplicate tokens from these processes is the key to gaining SYSTEM-level access, which is a prerequisite for obtaining TrustedInstaller privileges:

<div align="center">
  <a href="https://github.com/lucademers/WannaBeTrusted/assets/168311527/f928821a-8e30-4af5-92e9-c6eea5330b39">
    <img src="https://github.com/lucademers/WannaBeTrusted/assets/168311527/f928821a-8e30-4af5-92e9-c6eea5330b39"/>
  </a>
  <p><em><strong>Figure 4</strong> - Winlogon processes with PIDs 580 and 3540</em></p>
</div>

### **Step 5 - Checking Enabled Privileges**

Using the whoami /priv command, the current privileges of the user are displayed. Important privileges such as _SeTakeOwnershipPrivilege_, _SeLoadDriverPrivilege_, _SeBackupPrivilege_, and _SeRestorePrivilege_ are highlighted as enabled. These privileges are crucial for the subsequent steps in the privilege escalation process. To modify the code to change the enabled privileges, adjust the AdjustTokenPrivileges function call to include the desired privileges, allowing the user to enable other privileges as needed. Refer to lines 33 to 38 in the code for modification.

<div align="center">
  <a href="https://github.com/lucademers/WannaBeTrusted/assets/168311527/6b0b67e9-b461-400a-8c73-53b402db28f9">
    <img src="https://github.com/lucademers/WannaBeTrusted/assets/168311527/6b0b67e9-b461-400a-8c73-53b402db28f9" alt="Checking Enabled Privileges" width="600"/>
  </a>
  <p><em><strong>Figure 5 </strong> - Current user privileges </em></p>
</div>

### **Step 6 - Post-Escalation User Context**

The user context post-escalation is shown with the whoami /all command. The user is now operating under the nt authority\system account with the highest level of privileges available on the system, including membership in the 'TrustedInstaller' group. This confirms the successful execution of the WannaBeTrusted tool and the elevation to SYSTEM and TrustedInstaller privileges:

<div align="center">
  <a href="https://github.com/lucademers/WannaBeTrusted/assets/168311527/f786c701-3e30-4087-95b5-72d440814191">
    <img src="https://github.com/lucademers/WannaBeTrusted/assets/168311527/f786c701-3e30-4087-95b5-72d440814191" alt="Post-Escalation User Context" width="600"/>
  </a>
  <p><em><strong>Figure 6 </strong> - Post-escalation user context</em></p>
</div>

## Detailed Workflow

**1) Check if the program is running as an administrator:**

```c
if (!AmIAdmin()) {
    wprintf(L"This program must be run as an administrator.\n");
    return 1;
}
```

**Explanation:**

- This step verifies if the current process has administrative privileges using the AmIAdmin function;

- If not, it prints a message and exits, ensuring the tool is running with the required level of access.

**2) Enable necessary privileges in the current process token:**

```c
if (!EnableDebugPrivilege()) {
    wprintf(L"Failed to enable debug privilege.\n");
    return 1;
}
```

**Explanation:**

- This function enables the _SeDebugPrivilege_ for the current process, as it is  essential for manipulating the tokens of other processes.

**3) Obtain the PID of a process by its name:**

```c
if (!EnableDebugPrivilege()) {
    wprintf(L"Failed to enable debug privilege.\n");
    return 1;
}
```

**Explanation:**

- Using the function _GetProcessID_ to retrieve the PID of either winlogon.exe or services.exe by iterating through the running processes and matching the process name.

**4) Duplicate the token of a process using its PID:**

```c
HANDLE systemToken = NULL;
if (!MyDuplicateToken(pid, &systemToken)) {
    wprintf(L"Failed to duplicate token.\n");
    return 1;
}
```

**Explanation:**

- This function duplicates the token of the specified process PID;
- Using OpenProcess to get a handle to the target process;
- _OpenProcessToken_ is then used to get a handle to the target process's token;
- _DuplicateTokenEx_ is called to create a duplicate token with the necessary privileges.
  
**5) Impersonate SYSTEM privileges using winlogon.exe or services.exe:**

```c
if (ImpersonateLoggedOnUser(systemToken)) {
    wprintf(L"Impersonated SYSTEM token.\n");
} else {
    wprintf(L"Failed to impersonate SYSTEM token.\n");
    return 1;
}
```

**Explanation:**

- This step impersonates the SYSTEM account by using the duplicated token, which in turn allows the current process to adopt the security context of another user.

**6) Start the TrustedInstaller service if not running:**

```c
if (!StartTrustedInstallerService()) {
    wprintf(L"Failed to start TrustedInstaller service.\n");
    return 1;
}
```

**Explanation:**

Confirming whether the TrustedInstaller service is running by querying its status and starting it if necessary.

**7) Impersonate TrustedInstaller privileges:**

```c
HANDLE trustedInstallerToken = NULL;
if (!GetTrustedInstallerToken(&trustedInstallerToken)) {
    wprintf(L"Failed to obtain TrustedInstaller token.\n");
    return 1;
}
```

**Explanation:**

- This function duplicates the token of the TrustedInstaller process to impersonate it for the purpose of privilege escalation.

**8) Create a new process with the duplicated token:**

```c
if (CreateProcessWithToken(trustedInstallerToken, "cmd.exe")) {
    wprintf(L"Created process with TrustedInstaller token.\n");
} else {
    wprintf(L"Failed to create process with TrustedInstaller token.\n");
}
CloseHandle(trustedInstallerToken);
```

**Explanation:**

- This step involves using the _CreateProcessWithTokenW_ function to start a new process with elevated privileges.

## Prerequisites

- **Administrator Privileges:** Required to execute most operations within the tool;
- **C/C++ Compiler:**.

- # Usage

**1) Compile the Program:**

- MinGW is recommended due to its compatibility and ease of use with Windows API functions, avoiding some common compilation issues that may arise with other compilers like Visual Studio.

```c
x86_64-w64-mingw32-gcc -o WannaBeTrusted.exe -lpsapi -ladvapi32 -luserenv WannaBeTrusted.c

```

**2) Run the Program as Administrator:**

- Run the executable with administrative privileges.

## Disclaimer
WannaBeTrusted is provided "as is" without any warranty of any kind. The author is not responsible for any damage or legal issues caused by the use of this tool.

## Powered by
Luca Demers | LLB, MD | CRTO, OSCP, OSEP

https://lucademers.com 
lucademers [at] protonmail [dot]com
https://www.linkedin.com/in/lucademers/
