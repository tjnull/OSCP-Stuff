# Overview

The purpose of this directory is to provide resources, tools, and techniques that I used when I reviewed the AD section for the PEN-200/PWK

## Spawn Faerie

A powershell script that automated the building process and creates a vulnerable active directory environment. Orginally modified the script to make it work on Windows
Server 2016 so that it would run properly. This script was also used to build an vulnerable AD Challenge that would have been used for the Red Team Village CTF for Defcon 30. 

The script implements the following AD Attacks: 

- Abusing ACLs/ACEs
- Kerberoasting
- AS-REP Roasting
- Abuse DnsAdmins
- Password in Object Description
- User Objects With Default password (Changeme123!)
- Password Spraying
- DCSync
- Silver Ticket
- Golden Ticket 
- Pass-the-Hash
- Pass-the-Ticket
- SMB Signing Disabled

# Credit

- @WazeHell Orginial creator of the script. You can find it here: https://github.com/WazeHell/vulnerable-AD

## TO DO:

- Implement a procedure where it can import vulnerable templates for AD CS
- Test the script on other Server editions that are 2016 and up
- Include a AD Attack that focuses on attacking MSSQL
