---
title: Configuring ADCS CEPCES For Key-Based Certificate Renewal
description: A walkthrough on how to set up CEPCES for initial enrolment and subsequent key-based certificate renewal.
date: 2025-05-23 00:00:00 +0000
categories: []
tags: [PKI]
---

# Introduction

This guide covers implementation of CEPCES on a custom port other than 443 for certificate key-based renewal to take advantage of the automatic renewal feature of CEPCES.

## Scenario

This guide assumed the following pieces of infrastructure are in place:

1. An AD (Active Directory) forest called `example.com` that has an existing AD CS (Active Directory Certificate Services) PKI (public key infrastructure). The DC (Domain Controller) will be known as `DC001` , and the Issuing CA (Certificate Authority) will be known as `CA001`.
2. CEP and CES instances that are configured on a singular server, named `CEPCES001`. These services are assumed to be running under a service account called `cepcessvc`. This service account must be part of the `IIS_IUSRS` group on the `CEPCES001` server.
    1. One instance will use username and password for initial certificate enrolment, and the other instance will use certificate authentication for certificate renewal.
3. A `WORKGROUP` (non-domain-joined) computer which needs to a certificate. This will be known as the “End Entity” and will be named `CMP001`.
4. The connection from the end entity to the CEPCES service(s) over HTTPS will occur on a non-default port. In this case, that port will be 30000. This port is not used by any other service.

## High-Level Overview

Below is a high-level diagram of the communication flow between the different machines once this guide has been followed. 

![image.png](/assets/img/cepces/diagram.png)

# Implementation Instructions

## Configure the Certificate Template for Key-Based Renewal

Create a new certificate template to the desired specification, or copy an existing template, and configure the following settings of the template:

1. Within the `Subject Name` section of the certificate template’s properties, ensure that the `Supply in the Request` and `Use subject information from existing certificates for autoenrolment renewal request` options are ticked.
2. Within the `Issuance Requirements` tab, ensure that the `CA Certificate manager approval` option is ticked
3. Within the security tab, grant the `Read` and `Enroll` permissions to the `cepcessvc` service account.

![image.png](/assets/img/cepces/sn-settings.png)

![image.png](/assets/img/cepces/issue-settings.png)

Then issue the new certificate template to the CA. 

## Configure the CEPCES Server for Initial Enrolment

### Install CEPCES Initial Enrolment Instance

Use the following PowerShell commands to install the CEPCES instance and specify that username and password is required for authentication:

```powershell
Import-Module ServerManager
Add-WindowsFeature Adcs-Enroll-Web-Pol
Add-WindowsFeature Adcs-Enroll-Web-Svc
# Configure username/password authentication for CEP
Install-AdcsEnrollmentPolicyWebService \
	-AuthenticationType Username \
	-SSLCertThumbprint "<SSL_CERT_THUMBPRINT>"
	
# Install + Configure CES
Install-AdcsEnrollmentWebService \
	-ApplicationPoolIdentity
	-CAConfig "CA001.example.com\example-CA001-CA" \
	-SSLCertThumbprint "<SSL_CERT_THUMBPRINT>" \
	-AuthenticationType Username
```

In the above commands, `<SSL_CERT_THUMBPRINT>` refers to the thumbprint of the certificate to be used to bind to IIS.

The `Install-AdcsEnrollmentWebService` command installs the CES service to use the CA for the computer name [`CA001.example.com`](http://CA001.example.com) and the CA common name of `example-CA001-CA`. The identity of the CES is specified as the default application pool identity.

### Check IIS Manager Console

After a successful installation, you expect to see the following within the IIS (Internet Information Services) Manager console:

You can open the IIS Manager console by opening the Run menu and typing `inetmgr`.

![image.png](/assets/img/cepces/iis1.png)

Where `contoso.com` is replaced by your AD forest name (`example.com`, in this example).

Under `Default Web Site`, select the `ADPolicyProvider_CEP_UsernamePassword`, and then open `Application Settings`, noting the ID and the URI.

## Configure the CEPCES Server for Certificate-Based Renewal

This is performed on the same server, `CEPCES001`. As outlined in the introduction, the CEPCES Initial Enrolment and CEPCES certificate-based renewal instances will run on the same server, `CEPCES001`

### Install Renewal CEPCES Instance

This form configuration of renewal allows certificate clients to renew their certificate by using the key of their existing certificate to authenticate. When in key-based renewal mode, the service returns only certificate templates that are set for key-based renewal.

Use the following command to install CEP for renewal:

```powershell
# <SSL_CERT_THUMBPRINT> refers to the thumbprint of the certificate to bind to IIS
Install-AdcsEnrollmentPolicyWebService \
	-AuthenticationType Certificate
	-SSLCertThumbprint "<SSL_CERT_THUMBPRINT>"
	-KeyBasedRenewal
```

Use the following command to install and configure CES for renewal:

```powershell
# <SSL_CERT_THUMBPRINT> refers to the thumbprint of the certificate to bind to IIS
Install-AdcsEnrollmentWebService \
	-CAConfig "CA001.example.com\example-CA001-CA" \
	-SSLCertThumbprint "<SSL_CERT_THUMBPRINT>" \
	-AuthenticationType Certificate \
	-ServiceAccountName "example\cepcessvc" \
	-ServiceAccountPassword (read-host "Set user password" -assecurestring) \
	-RenewalOnly \
	-AllowKeyBasedRenewal
```

In this command, the identity of the CES Service is specified as the `cepcessvc` service account.

The `RenewalOnly` options lets CES run in renewal-only mode, and the `AllowKeyBasedRenewal` option specifies that the CES service accepts key-based renewal request, as outlined at the beginning of this section.

### Check IIS Manager Console

After a successful installation, you expect to see the following within the IIS (Internet Information Services) Manager console:

You can open the IIS Manager console by opening the Run menu and typing `inetmgr`.

![image.png](/assets/img/cepces/iis2.png)

Where `contoso.com` is replaced by your AD forest name (`example.com`, in this example).

Under `Default Web Site`, select the `KeyBaedRenewal_ADPolicyProvider_CEP_Certificate`, and then open `Application Settings`, noting the ID and the URI.

If the ID and the URI obtained at this point is different from the ID and URI obtained during the Initial Enrolment CEPCES instance setup, then you can copy and paste the value so that they match.

## Configure Constrained Delegation on the Service Account

In order for certificate-based renewal to work, the CES service must be able to impersonate clients that authenticate using a certificate. This is accomplished using **Kerberos constrained delegation** with protocol transition (S4U).

### Configure TrustedToAuthForDelegation and Delegation Targets

Run the following PowerShell commands from a domain-joined management workstation or directly on a domain controller:

```powershell
# Enable protocol transition (S4U2Self) for the service account
Get-ADUser -Identity cepcessvc | Set-ADAccountControl -TrustedToAuthForDelegation $true

# Allow delegation to the CA (host and RPCSS SPNs)
Set-ADUser -Identity cepcessvc -Add @{
  'msDS-AllowedToDelegateTo' = @(
    'HOST/CA001.example.com',
    'RPCSS/CA001.example.com'
  )
}

```

This grants the CES service account (`cepcessvc`) the ability to impersonate clients and delegate those identities to the CA server (`CA001`).

> Note: The service account must be a member of the IIS_IUSRS group on CEPCES001.
> 

---

## Create AD Computer Object for Workgroup Client

Although the client (`CMP001`) is not joined to the domain, a corresponding computer object must exist in Active Directory. This allows:

- The CA to associate and publish the certificate to the AD object.
- Delegation to succeed during renewal (as CES impersonates the AD object).

### Steps:

1. Open **Active Directory Users and Computers** on `DC001`.
2. Create a new computer object named `CMP001` in an appropriate OU.
3. Do not attempt to join the actual machine to the domain.

---

## Configure IIS to Use Custom Port (30000)

### Steps:

1. On `CEPCES001`, open **IIS Manager** (`inetmgr`).
2. Select `Default Web Site`.
3. In the **Actions** pane, click **Bindings...**
4. Edit the HTTPS binding:
    - Change the port from `443` to `30000`.
    - Ensure the correct SSL certificate is selected.
5. Confirm and apply the changes.

> Ensure TCP port 30000 is allowed through Windows Firewall and any upstream network firewalls.
> 

---

## Update msPKI-Enrolment-Servers in Active Directory

Active Directory maintains a list of enrolment service URIs under the CA object in the configuration partition. This must be updated to reflect your custom port and both CEP/CES instances.

### Steps:

1. On `DC001`, open **`adsiedit.msc`**.
2. Connect to the **Configuration** naming context.
3. Navigate to:
    
    ```
    CN=CA001,CN=Enrollment Services,CN=Public Key Services,
    CN=Services,CN=Configuration,DC=example,DC=com
    
    ```
    
4. Right-click the CA object and choose **Properties**.
5. Locate the **`msPKI-Enrolment-Servers`** attribute.
6. Add or update values similar to the following:
    
    ```
    140https://cepces001.example.com:30000/ENTCA_CES_UsernamePassword/service.svc/CES0
    181https://cepces001.example.com:30000/ENTCA_CES_Certificate/service.svc/CES1
    ```
    

> These correspond to the URI paths discovered in IIS under Application Settings for each instance.
> 

---

## Configure CMP001 Client for Initial Enrolment and Renewal

On the workgroup machine `CMP001`, local Group Policy must be configured to recognize the CEP instances and handle auto-enrolment.

### 1. Open Local Group Policy Editor

Run:

```
gpedit.msc
```

Navigate to:

```
Computer Configuration > Windows Settings > Security Settings > Public Key Policies
```

### 2. Enable Auto-Enrolment

- Open **Certificate Services Client - Auto-Enrolment**
- Set to **Enabled**, with:
    - **Renew expired certificates**
    - **Update certificates that use certificate templates**
    - **Automatically enrol certificates**

### 3. Configure Certificate Enrolment Policy (Initial)

- Open **Certificate Services Client - Certificate Enrolment Policy**
- Click **Add...**
- Enter the URI for the **Username/Password** CEP instance:
    
    ```
    https://cepces001.example.com:30000/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP0
    
    ```
    
- Set Authentication to **Username and Password**
- Set Priority to `10`

### 4. Enrol First Certificate

- Run `certlm.msc`
- Right-click **Personal > Certificates** > **All Tasks > Request New Certificate**
- Follow the wizard and select the new KBR template

### 5. Configure Certificate Enrolment Policy (Renewal)

- Open **Certificate Services Client - Certificate Enrolment Policy** again
- Click **Add...**
- Enter the URI for the **Certificate-authenticated** CEP instance:
    
    ```
    https://cepces001.example.com:30000/KeyBasedRenewal_ADPolicyProvider_CEP_Certificate/service.svc/CEP1
    ```
    
- Set Authentication to **Certificate**
- Set Priority to `1`

> This ensures renewal always prefers certificate-based CEP.
> 

---

Your CEPCES infrastructure is now fully configured for secure initial enrolment and automated certificate-based renewal over a non-standard HTTPS port.