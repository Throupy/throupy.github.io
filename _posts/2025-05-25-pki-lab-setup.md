---
title: Setting up a Lab Environment for PKI Investigations
description: A walkthrough on how to set up a virtualised lab environment for testing and investigating ADCS.
date: 2025-05-25 00:00:00 +0000
categories: []
tags: [PKI, active directory, windows]
---

# Introduction

This guide provides step-by-step instructions for creating a virtualized lab environment to practice configuring and investigating various aspects of Active Directory Certificate Services (ADCS). The environment simulates a basic enterprise Public Key Infrastructure (PKI) setup with:

- A domain controller (`DC001`)
- An online enterprise root certificate authority (`CA001`)
- A domain-joined workstation (`PC001`)

The lab is designed using VMware Workstation Pro 17 and evaluation versions of Windows obtained from the Microsoft Evaluation Center.

## Software and Resources Required

- **Windows Server 2022 ISO** (for `DC001` and `CA001`)
- **Windows 10 Enterprise ISO** (for `PC001`)
- **VMware Workstation Pro 17**

## Network and Host Overview

| Component | Hostname | IP Address | Role |
| --- | --- | --- | --- |
| DC | DC001 | 192.168.100.10 | Domain Controller + DNS |
| CA | CA001 | 192.168.100.11 | Enterprise Root CA |
| Client | PC001 | 192.168.100.12 | Domain-joined Workstation |

---

# Step-by-Step Setup Instructions

## 1. Creating the Virtual Network

1. Launch **VMware Workstation Pro**
2. Navigate to **Edit > Virtual Network Editor**
3. Click **Change Settings** (respond to UAC if prompted)
4. Click **Add Network**, select a network (e.g., `VMnet18`)
5. Rename it to `PKI_LAB` for clarity
6. Configure the network:
    - **Host-Only**
    - **Disable DHCP Server**
    - **Set subnet** to `192.168.100.0`
    - **Set subnet mask** to `255.255.255.0`
7. Click **OK** to apply and exit

## 2. Creating the Virtual Machines

For each VM (`DC001`, `CA001`, and `PC001`):

1. Click **Create a New Virtual Machine** in VMware
2. Use the following configuration:
    - RAM: 4 GB minimum
    - Disk: 40 GB minimum (dynamically allocated)
    - NIC: Connect to `PKI_LAB` network
    - Boot from the appropriate ISO
3. Proceed with Windows installation and assign computer names accordingly

## 3. Configure Static IP Addresses

After installation, assign static IPs:

1. Navigate to:
`Control Panel > Network and Sharing Center > Change Adapter Settings`
2. Right-click **Ethernet** > **Properties** > **Internet Protocol Version 4 (TCP/IPv4)**
3. Configure manually:
    - **DC001**: IP `192.168.100.10`, Gateway `192.168.100.1`, DNS `192.168.100.10`
    - **CA001**: IP `192.168.100.11`, Gateway `192.168.100.1`, DNS `192.168.100.10`
    - **PC001**: IP `192.168.100.12`, Gateway `192.168.100.1`, DNS `192.168.100.10`

## 4. Promote DC001 to a Domain Controller

1. Log in to `DC001` as Administrator
2. Open PowerShell (Run as Administrator):

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -InstallDNS
```

1. Reboot when prompted

## 5. Join CA001 and PC001 to the Domain

On **CA001** and **PC001**:

```powershell
Add-Computer -DomainName "lab.local" -Restart
```

Enter domain admin credentials when prompted.

## 6. Configure the Enterprise Root CA (CA001)

On **CA001**:

```powershell
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools

Install-AdcsCertificationAuthority `
  -CAType EnterpriseRootCA `
  -CACommonName "CA001" `
  -KeyLength 2048 `
  -HashAlgorithmName SHA256 `
  -ValidityPeriod Years -ValidityPeriodUnits 10 `
  -Force
```

## 7. Create a Dedicated Domain Admin User

On **DC001**:

```powershell
New-ADUser -Name "PKI Admin" `
           -GivenName "PKI" `
           -Surname "Admin" `
           -SamAccountName "pkiadmin" `
           -UserPrincipalName "pkiadmin@lab.local" `
           -AccountPassword (Read-Host -AsSecureString "Enter password") `
           -Enabled $true

Add-ADGroupMember -Identity "Domain Admins" -Members "pkiadmin"
```

Use this account for future administration tasks.

---

# Final Notes

- Ensure time is synchronized between VMs (important for Kerberos)
- Consider taking snapshots at each major milestone
- Enable Auto Enrolment and publish certificate templates as needed
- Monitor via Event Viewer and use `certutil -pulse` and `certlm.msc` for testing