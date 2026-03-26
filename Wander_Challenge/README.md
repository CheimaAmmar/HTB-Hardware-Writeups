# HTB Printer — PJL Exploitation Writeup

## 1. Introduction

This challenge provides a target IP address and port exposing a web-based interface used to interact with a network printer. The interface includes a feature named **"Job Controls"**, which allows users to submit PJL (Printer Job Language) commands and receive their output.

The objective is to analyze this interface, identify potential vulnerabilities, and extract sensitive information from the underlying system.

---

## 2. Initial Observation

Upon accessing the web interface, a command input field is available. Any PJL command entered is directly processed and executed by the printer backend.

This behavior indicates:
- Lack of input sanitization
- Direct exposure of a low-level printer control interface

This creates an opportunity for abuse of PJL commands.

---

## 3. PJL and File System Interaction

PJL provides several commands that allow interaction with the printer's internal file system. The relevant commands for this challenge include:

- `FSDIRLIST` — list directory contents  
- `FSQUERY` — check file existence  
- `FSUPLOAD` — read file content  
- `FSDOWNLOAD` — write files  

These commands can be leveraged to explore and access the file system.

---

## 4. File System Enumeration

The enumeration process begins by listing the root directory:


@PJL FSDIRLIST NAME="0:" ENTRY=1


This reveals multiple directories such as:


PJL
PostScript
saveDevice
webServer


At this stage, the attacker must adopt an **exploratory approach**, systematically inspecting directories to identify potentially sensitive locations.

---

## 5. Path Traversal Vulnerability

By testing path traversal sequences, it is possible to escape the restricted printer file system:


@PJL FSDIRLIST NAME="0:/../" ENTRY=1


This exposes system-level directories:


etc
conf
home
rw
tmp


This confirms a **path traversal vulnerability**, allowing access to the underlying operating system.

---

## 6. Target Discovery Strategy

To retrieve the flag, it is necessary to **search across all accessible directories and files**, focusing on locations that may contain user data or application-specific content.

This includes:
- User directories (`/home`)
- Configuration folders (`/conf`)
- Writable areas (`/rw`, `/tmp`)
- Application-related directories

The process is iterative:
1. Enumerate directories  
2. Identify files  
3. Inspect files for meaningful content  

---

## 7. Identifying the Target File

Exploring the user directory:


@PJL FSDIRLIST NAME="0:/../home/default" ENTRY=1


Reveals:


readyjob TYPE=FILE SIZE=457


This file appears non-standard and is likely associated with the application logic, making it a strong candidate for containing sensitive data.

---

## 8. Extracting File Content

To read the file, the `FSUPLOAD` command must be used with proper parameters:


@PJL FSUPLOAD NAME="0:/../home/default/readyjob" OFFSET=0 SIZE=457


Important:
- `OFFSET` specifies the starting byte
- `SIZE` specifies the number of bytes to read
- Incorrect or incomplete syntax results in errors such as `FILEERROR=3`

---

## 9. Result

The contents of the identified file were successfully extracted using the `FSUPLOAD` command.

The retrieved data confirms that sensitive information can be accessed through the exploited vulnerability. This validates the effectiveness of the enumeration and traversal approach used throughout the attack.


---

## 10. Vulnerability Analysis

This challenge demonstrates multiple security issues:

### 10.1 Unrestricted PJL Access
The interface allows direct execution of PJL commands without validation.

### 10.2 Path Traversal
The use of `../` enables access outside the intended file system.

### 10.3 Arbitrary File Read
Attackers can read any accessible file using `FSUPLOAD`.

---

## 11. Conclusion

This exploitation highlights the risks of exposing printer control interfaces without proper restrictions.

An attacker can:
- Enumerate internal file systems
- Traverse directories
- Extract sensitive files

The key to solving the challenge lies in **systematic exploration and careful inspection of files**, rather than targeting a single predefined location.
