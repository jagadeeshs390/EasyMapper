"""
EasyMapper Port Knowledge Base
Contains descriptions, risk levels, theoretical exploitation vectors, and remediation advice
for common network ports and services.
"""

PORT_DATABASE = {
    21: {
        "service": "FTP (File Transfer Protocol)",
        "description": "Standard network protocol used for the transfer of computer files between a client and server.",
        "risk": "High",
        "risk_explanation": "Transmits credentials and data in cleartext; legacy daemons often have misconfigurations or unpatched vulnerabilities.",
        "exploit_vectors": [
            "Cleartext credential sniffing and interception on local or transit networks.",
            "Anonymous login misconfigurations allowing unauthorized access to sensitive files or writable directories.",
            "Cross-Site FTP Printing (FXP) and bounce attacks targeting internal network services.",
            "Known vulnerabilities (e.g., backdoor or buffer overflows in legacy vsftpd, ProFTPD, or Pure-FTPd versions)."
        ],
        "remediation": [
            "Enforce SFTP (over SSH) or FTPS (FTP over TLS/SSL) instead of plaintext FTP.",
            "Disable anonymous user access unless strictly intended for public read-only assets.",
            "Confine users to their home directory (chroot jail) and enforce strong password policies.",
            "Restrict access via firewall or security group to trusted source IP addresses."
        ]
    },
    22: {
        "service": "SSH (Secure Shell)",
        "description": "Cryptographic network protocol for operating network services securely over an unsecured network.",
        "risk": "Medium",
        "risk_explanation": "Standard remote management gateway. Secure by default, but target for brute force attacks and credential stuffing.",
        "exploit_vectors": [
            "Automated brute-force and dictionary attacks attempting common usernames (root, admin) and weak passwords.",
            "Credential stuffing using leaked credential databases.",
            "Vulnerabilities in outdated OpenSSH versions (e.g., RegreSSHion CVE-2024-6387, Terrapin attack CVE-2023-48795).",
            "Exposed private keys or compromised agent forwarding."
        ],
        "remediation": [
            "Disable password authentication (`PasswordAuthentication no`) in favor of Ed25519/RSA SSH keys.",
            "Disable direct root login (`PermitRootLogin no`).",
            "Deploy Fail2ban or CrowdSec to automatically rate-limit and ban aggressive brute-force attempts.",
            "Restrict SSH access via VPN or firewall whitelisting; consider changing default port 22."
        ]
    },
    23: {
        "service": "Telnet",
        "description": "Legacy bidirectional interactive text-oriented communication facility using unencrypted virtual terminal connections.",
        "risk": "Critical",
        "risk_explanation": "Completely unencrypted protocol. All authentication credentials, keystrokes, and commands are sent in plaintext.",
        "exploit_vectors": [
            "Passive network packet sniffing revealing administrative usernames and passwords instantly.",
            "Man-in-the-Middle (MitM) session hijacking and command injection.",
            "Automated IoT botnet scanning and credential spraying (e.g., Mirai botnet family targeting default Telnet accounts)."
        ],
        "remediation": [
            "Immediately disable and decommission the Telnet service daemon (`systemctl disable telnet.socket`).",
            "Replace all administrative Telnet connections with SSH.",
            "Block port 23 at edge and internal firewalls."
        ]
    },
    25: {
        "service": "SMTP (Simple Mail Transfer Protocol)",
        "description": "Internet standard communication protocol for electronic mail transmission.",
        "risk": "Medium",
        "risk_explanation": "Can be exploited for spam relaying, email spoofing, and internal username enumeration if misconfigured.",
        "exploit_vectors": [
            "Open Relay exploitation: Relaying millions of spam or phishing emails through the server, causing domain blacklisting.",
            "User enumeration using SMTP commands such as `VRFY`, `EXPN`, and `RCPT TO`.",
            "Mail spoofing if SPF, DKIM, and DMARC DNS records are absent or not enforced.",
            "Legacy mail transfer agent vulnerabilities (e.g., Exim or Postfix memory corruption CVEs)."
        ],
        "remediation": [
            "Ensure open relaying is disabled; require authentication (SMTP-AUTH) for outgoing mail.",
            "Disable `VRFY` and `EXPN` commands in the mail server configuration.",
            "Enforce opportunistic or mandatory TLS encryption (STARTTLS).",
            "Configure robust SPF, DKIM, and DMARC DNS policies for the sending domain."
        ]
    },
    53: {
        "service": "DNS (Domain Name System)",
        "description": "Hierarchical decentralized naming system for computers, services, or resources on the internet.",
        "risk": "Medium",
        "risk_explanation": "Can leak internal network infrastructure maps via zone transfers and be abused for DDoS amplification.",
        "exploit_vectors": [
            "Unrestricted DNS Zone Transfers (AXFR): Attackers retrieve the full list of subdomains, internal hosts, and IP addresses.",
            "DNS Amplification / Reflection DDoS: Open resolvers abused to flood target victims with large responses to spoofed UDP requests.",
            "DNS Cache Poisoning / Kaminsky attacks redirecting legitimate traffic to malicious IP addresses.",
            "Vulnerabilities in BIND or dnsmasq implementations."
        ],
        "remediation": [
            "Disable recursive queries for external clients (close open resolver).",
            "Strictly restrict zone transfers (`allow-transfer { trusted_servers; };`) only to authorized secondary nameservers.",
            "Implement DNS Response Rate Limiting (RRL) to mitigate amplification abuse.",
            "Enable DNSSEC to prevent spoofing and cache poisoning."
        ]
    },
    69: {
        "service": "TFTP (Trivial File Transfer Protocol)",
        "description": "Simple lockstep file transfer protocol used primarily for automated bootstrapping and network hardware configuration.",
        "risk": "High",
        "risk_explanation": "Has no authentication, encryption, or directory traversal safeguards by default.",
        "exploit_vectors": [
            "Unauthenticated extraction of network device configurations, firmware images, and credential backups.",
            "Directory traversal attacks retrieving sensitive host files (e.g., `/etc/passwd`).",
            "Arbitrary file upload to overwrite boot images or system files."
        ],
        "remediation": [
            "Do not expose TFTP to public or untrusted network segments.",
            "Confine TFTP to an isolated root directory with read-only permissions where feasible.",
            "Migrate network provisioning to secure protocols like SFTP or HTTPS."
        ]
    },
    80: {
        "service": "HTTP (Hypertext Transfer Protocol)",
        "description": "Foundation of data communication for the World Wide Web, operating without transport encryption.",
        "risk": "Medium",
        "risk_explanation": "Web traffic is unencrypted; subject to eavesdropping, credential interception, and application-layer vulnerabilities.",
        "exploit_vectors": [
            "Cleartext transmission of session cookies, authentication tokens, and sensitive customer data.",
            "Man-in-the-Middle (MitM) attacks injecting malicious scripts, advertisements, or redirects.",
            "Web application vulnerabilities: OWASP Top 10 (SQL Injection, Cross-Site Scripting, Command Injection, SSRF).",
            "Web server information disclosure via verbose error pages, directory indexing, or server banner leaks."
        ],
        "remediation": [
            "Redirect all HTTP port 80 traffic to HTTPS (port 443) using HTTP 301 redirects.",
            "Enable HTTP Strict Transport Security (HSTS) with `preload`.",
            "Disable directory listing (`Options -Indexes` or `autoindex off`).",
            "Deploy a Web Application Firewall (WAF) and audit web applications regularly."
        ]
    },
    110: {
        "service": "POP3 (Post Office Protocol v3)",
        "description": "Application-layer Internet standard protocol used by local email clients to retrieve email from a remote server.",
        "risk": "High",
        "risk_explanation": "Plaintext email retrieval protocol vulnerable to passive sniffing and credential theft.",
        "exploit_vectors": [
            "Sniffing of email user login credentials and email message contents over unencrypted networks.",
            "Brute force and dictionary attacks against mailbox accounts.",
            "Buffer overflow vulnerabilities in older POP3 server implementations."
        ],
        "remediation": [
            "Disable unencrypted POP3 on port 110.",
            "Enforce secure POP3 over TLS (POP3S) on port 995, or migrate to IMAPS.",
            "Require modern multi-factor authentication (MFA) via OAuth2 for mail access."
        ]
    },
    111: {
        "service": "rpcbind / portmapper",
        "description": "RPC (Remote Procedure Call) portmapper mapping ONC RPC program numbers to network port numbers.",
        "risk": "High",
        "risk_explanation": "Exposes internal RPC services and is frequently abused in reflection DDoS attacks and network reconnaissance.",
        "exploit_vectors": [
            "Information enumeration: Listing all registered RPC services, NFS shares, and NIS domains.",
            "UDP-based reflection and amplification DDoS attacks against third parties.",
            "Indirect exploitation of vulnerable underlying RPC services (e.g., status, rpc.mountd, nfs)."
        ],
        "remediation": [
            "Block port 111 at external firewalls; rpcbind should never be publicly reachable.",
            "Bind RPC services only to localhost or trusted internal interfaces.",
            "Disable unused RPC services on the host."
        ]
    },
    135: {
        "service": "MSRPC (Microsoft Windows RPC)",
        "description": "Microsoft Windows RPC endpoint mapper used for client-to-server and server-to-server communication.",
        "risk": "High",
        "risk_explanation": "Exposes Windows endpoints to remote enumeration and historical remote code execution flaws.",
        "exploit_vectors": [
            "Remote enumeration of endpoints, interfaces, and user sessions via `rpcdump` or `rpcclient`.",
            "DCOM / WMI remote command execution during lateral movement.",
            "Vulnerabilities in MS-RPC services (e.g., PetitPotam NTLM relay coercion, PrintNightmare)."
        ],
        "remediation": [
            "Block port 135 at the network perimeter firewall.",
            "Disable unneeded DCOM protocols and restrict remote RPC access.",
            "Segment Windows domain controllers and member servers from untrusted networks."
        ]
    },
    139: {
        "service": "NetBIOS Session Service",
        "description": "NetBIOS over TCP/IP (NetBT) session service for file and printer sharing in Windows environments.",
        "risk": "High",
        "risk_explanation": "Legacy Windows networking protocol leaking sensitive host and workgroup metadata.",
        "exploit_vectors": [
            "Network reconnaissance leaking computer names, domain membership, user lists, and MAC addresses.",
            "SMB-over-NetBIOS authentication relay attacks (NTLM capture/relay via tools like Responder).",
            "Null-session enumeration disclosing shared drives and security policies."
        ],
        "remediation": [
            "Disable NetBIOS over TCP/IP in Windows network adapter properties.",
            "Block ports 137, 138, and 139 at network firewalls.",
            "Standardize on SMBv2/v3 directly over port 445."
        ]
    },
    143: {
        "service": "IMAP (Internet Message Access Protocol)",
        "description": "Internet standard protocol used by email clients to retrieve and synchronize messages with a mail server.",
        "risk": "Medium",
        "risk_explanation": "Transmits credentials and emails in cleartext unless TLS/STARTTLS is explicitly enforced.",
        "exploit_vectors": [
            "Cleartext credential interception and email snooping.",
            "Credential stuffing and brute-force attacks against user mailboxes.",
            "Denial of service via resource-intensive search/sync commands on unauthenticated connections."
        ],
        "remediation": [
            "Enforce IMAPS (IMAP over TLS) on port 993 and disable plaintext port 143.",
            "Mandate STARTTLS if port 143 must remain active for backward compatibility.",
            "Enable rate-limiting and intrusion prevention (Fail2ban)."
        ]
    },
    161: {
        "service": "SNMP (Simple Network Management Protocol)",
        "description": "Protocol for managing and monitoring network devices including routers, switches, servers, and printers.",
        "risk": "High",
        "risk_explanation": "SNMPv1/v2c use plaintext community strings; default 'public' or 'private' strings leak full configuration and topology.",
        "exploit_vectors": [
            "Default community string brute forcing ('public', 'private') leading to comprehensive information disclosure.",
            "Extracting running process lists, network routes, usernames, and interface statistics.",
            "Modifying device settings or rebooting equipment if write community strings ('private') are active.",
            "SNMP reflection DDoS amplification attacks over UDP."
        ],
        "remediation": [
            "Upgrade to SNMPv3, which provides cryptographic authentication (SHA-2) and encryption (AES).",
            "Change default community strings to long, randomly generated secrets.",
            "Restrict SNMP access strictly to authorized monitoring stations via Access Control Lists (ACLs) and firewalls."
        ]
    },
    389: {
        "service": "LDAP (Lightweight Directory Access Protocol)",
        "description": "Open protocol for accessing and maintaining distributed directory information services over an IP network.",
        "risk": "High",
        "risk_explanation": "Unencrypted directory access allowing reconnaissance of entire organization user and group hierarchies.",
        "exploit_vectors": [
            "Anonymous LDAP binds disclosing usernames, email addresses, phone numbers, and Active Directory structures.",
            "Cleartext credential sniffing during simple LDAP authentication binds.",
            "LDAP injection vulnerabilities in applications communicating with directory servers.",
            "Abuse as an amplification vector for UDP-based reflection DDoS attacks (CLDAP on port 389 UDP)."
        ],
        "remediation": [
            "Disable anonymous directory binds.",
            "Enforce LDAPS (LDAP over SSL/TLS) on port 636 or mandate STARTTLS on port 389.",
            "Block public internet access; confine LDAP to internal corporate networks."
        ]
    },
    443: {
        "service": "HTTPS (HTTP Secure)",
        "description": "HTTP encrypted using Transport Layer Security (TLS/SSL) for secure web communication.",
        "risk": "Low",
        "risk_explanation": "Standard secure web port. While transport is encrypted, the web application running behind it may have vulnerabilities.",
        "exploit_vectors": [
            "Web application attacks (SQL Injection, XSS, CSRF, File Inclusion, Deserialization, SSRF).",
            "Outdated TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) vulnerable to cryptographic downgrade attacks (e.g., POODLE, BEAST).",
            "Weak cipher suites enabling eavesdropping.",
            "Expired, self-signed, or improperly configured TLS certificates."
        ],
        "remediation": [
            "Configure modern TLS (TLS 1.2 and TLS 1.3 only) with forward-secret cipher suites (ECDHE).",
            "Enforce strong HTTP security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options.",
            "Regularly patch web servers and backend application dependencies.",
            "Use automated SSL certificate renewal (e.g., Let's Encrypt / Certbot)."
        ]
    },
    445: {
        "service": "SMB (Server Message Block) / Microsoft-DS",
        "description": "Network communication protocol for sharing files, printers, serial ports, and miscellaneous communications.",
        "risk": "Critical",
        "risk_explanation": "High-profile target for remote code execution exploits, lateral movement, and ransomware propagation.",
        "exploit_vectors": [
            "Critical Remote Code Execution exploits (e.g., EternalBlue / MS17-010, SMBGhost / CVE-2020-0796).",
            "NTLM hash relay attacks and Pass-the-Hash exploitation against unhardened environments.",
            "Unauthorized access to open/guest administrative shares (C$, ADMIN$, IPC$).",
            "Primary infection vector for destructive ransomware (WannaCry, NotPetya)."
        ],
        "remediation": [
            "NEVER expose port 445 directly to the public internet; block it at border firewalls.",
            "Completely disable legacy SMBv1 across all systems.",
            "Enforce SMB signing and SMB encryption (SMBv3).",
            "Restrict access strictly to trusted local administration subnets."
        ]
    },
    636: {
        "service": "LDAPS (LDAP over SSL)",
        "description": "Secure variant of LDAP operating over an encrypted TLS connection.",
        "risk": "Medium",
        "risk_explanation": "Encrypted directory service. Exposure may allow directory enumeration if compromised credentials are used.",
        "exploit_vectors": [
            "Password spraying and brute-forcing against Active Directory / LDAP accounts.",
            "Directory reconnaissance if valid service account credentials are leaked.",
            "Certificate validation bypass or weak TLS cipher negotiation."
        ],
        "remediation": [
            "Restrict access to internal administrative subnets or VPN gateways.",
            "Enforce account lockout policies and multi-factor authentication (MFA).",
            "Ensure valid certificates are installed and weak ciphers are disabled."
        ]
    },
    873: {
        "service": "rsync",
        "description": "Remote file and directory synchronization utility.",
        "risk": "High",
        "risk_explanation": "Frequently misconfigured without authentication, enabling complete read and write access to filesystems.",
        "exploit_vectors": [
            "Anonymous / unauthenticated rsync modules allowing attackers to download source code, database dumps, and backups.",
            "Overwriting system files or uploading web shells to gain remote code execution.",
            "Cleartext credential transmission in standard rsync daemon configurations."
        ],
        "remediation": [
            "Require authentication with strong passwords in `rsyncd.conf`.",
            "Tunnel rsync exclusively through SSH (`rsync -e ssh`) rather than running a standalone rsync daemon.",
            "Restrict module access to designated source IP addresses."
        ]
    },
    1433: {
        "service": "Microsoft SQL Server (MSSQL)",
        "description": "Relational database management system developed by Microsoft.",
        "risk": "High",
        "risk_explanation": "Database service containing sensitive business records. If breached, can lead to host command execution.",
        "exploit_vectors": [
            "Brute forcing default administrative accounts (e.g., `sa`).",
            "Post-authentication command execution via extended stored procedures (e.g., `xp_cmdshell`).",
            "Data exfiltration and unauthorized schema manipulation.",
            "SQL Server Resolution Protocol (SSRP) amplification attacks over UDP port 1434."
        ],
        "remediation": [
            "Do not expose database ports to the internet; place behind application firewalls or private subnets.",
            "Disable the `sa` account or assign a complex, randomized 32+ character password.",
            "Disable `xp_cmdshell` and unused extended stored procedures.",
            "Enforce TLS encryption for client-server database connections."
        ]
    },
    1521: {
        "service": "Oracle Database Listener",
        "description": "Network listener service for Oracle Database connections.",
        "risk": "High",
        "risk_explanation": "Direct access to enterprise Oracle databases; listener can be enumerated for valid SIDs and databases.",
        "exploit_vectors": [
            "SID (System Identifier) enumeration and brute-force discovery.",
            "TNS listener poisoning allowing MitM interception of database credentials.",
            "Brute-forcing default accounts (e.g., `SYS`, `SYSTEM`, `SCOTT/TIGER`).",
            "Exploitation of PL/SQL injection flaws to gain operating system privileges."
        ],
        "remediation": [
            "Protect listener with a secure password (`ADMIN_RESTRICTIONS_listener = ON`).",
            "Lock and expire default accounts; enforce strong password policies.",
            "Restrict listener port 1521 to trusted application servers via firewall rules."
        ]
    },
    2049: {
        "service": "NFS (Network File System)",
        "description": "Distributed file system protocol allowing a client computer to access files over a computer network.",
        "risk": "Critical",
        "risk_explanation": "Permissive export configurations can grant full remote root access to the underlying server filesystem.",
        "exploit_vectors": [
            "Mounting exposed exports without authentication to read private files, source code, and secrets.",
            "`no_root_squash` misconfiguration: Attackers create setuid root binaries on the mount to obtain root access on the NFS server.",
            "IP address spoofing to bypass weak host-based authorization lists."
        ],
        "remediation": [
            "Never expose NFS port 2049 to public networks.",
            "Always enable `root_squash` in `/etc/exports` unless strictly necessary.",
            "Implement NFSv4 with Kerberos (RPCSEC_GSS) for cryptographic authentication.",
            "Strictly define client IP masks in export definitions."
        ]
    },
    3306: {
        "service": "MySQL Database",
        "description": "Popular open-source relational database management system.",
        "risk": "High",
        "risk_explanation": "Directly accessible database instances are vulnerable to brute-force attacks and privilege escalation.",
        "exploit_vectors": [
            "Automated credential brute forcing against `root` or application service accounts.",
            "Exploiting User-Defined Functions (UDF) to execute arbitrary operating system commands from SQL.",
            "Reading local files via `LOAD DATA LOCAL INFILE` misconfigurations.",
            "Unauthorized access leading to complete data exfiltration, tampering, or ransomware wiping."
        ],
        "remediation": [
            "Bind MySQL strictly to `127.0.0.1` or internal VPC networks (`bind-address = 127.0.0.1`).",
            "Disable remote root access; create application accounts with least-privilege permissions.",
            "Enforce SSL/TLS for all database connections.",
            "Disable `local_infile` in `my.cnf`."
        ]
    },
    3389: {
        "service": "RDP (Remote Desktop Protocol)",
        "description": "Microsoft proprietary protocol providing a graphical interface for connecting to another computer.",
        "risk": "Critical",
        "risk_explanation": "Primary initial access vector for ransomware operators; subject to intense brute-force and remote code execution exploits.",
        "exploit_vectors": [
            "RDP brute force and credential stuffing attacks yielding interactive desktop access.",
            "Pre-authentication Remote Code Execution vulnerabilities (e.g., BlueKeep / CVE-2019-0708).",
            "Session hijacking via sticky keys or unconstrained delegation.",
            "Direct installation and execution of ransomware payloads."
        ],
        "remediation": [
            "Never expose RDP port 3389 directly to the internet; require a secure VPN with MFA.",
            "Enforce Network Level Authentication (NLA).",
            "Implement Account Lockout policies to prevent automated dictionary attacks.",
            "Deploy multi-factor authentication (MFA) via solutions like Duo or Microsoft Authenticator."
        ]
    },
    5432: {
        "service": "PostgreSQL Database",
        "description": "Advanced, open-source object-relational database system.",
        "risk": "High",
        "risk_explanation": "Direct database exposure risks unauthorized access, credential brute-forcing, and OS command execution.",
        "exploit_vectors": [
            "Brute forcing standard `postgres` administrator account credentials.",
            "Executing system commands via `COPY ... FROM PROGRAM` when holding superuser privileges.",
            "Data exfiltration, deletion, or manipulation of business databases.",
            "Overly permissive `pg_hba.conf` rules (e.g., `trust` method from remote hosts)."
        ],
        "remediation": [
            "Bind PostgreSQL strictly to `localhost` or private internal interfaces (`listen_addresses = 'localhost'`).",
            "Ensure `pg_hba.conf` strictly enforces `scram-sha-256` password authentication and trusted subnets.",
            "Revoke superuser privileges from routine application database accounts.",
            "Audit database connections and enforce TLS encryption."
        ]
    },
    5900: {
        "service": "VNC (Virtual Network Computing)",
        "description": "Graphical desktop-sharing system using the Remote Frame Buffer (RFB) protocol.",
        "risk": "High",
        "risk_explanation": "Often configured with weak or no passwords, giving attackers immediate graphical mouse and keyboard control.",
        "exploit_vectors": [
            "Unauthenticated VNC access providing immediate remote desktop takeover.",
            "Brute-forcing weak, 8-character-limited legacy DES VNC passwords.",
            "Unencrypted screen streaming allowing passive video interception and credential capture."
        ],
        "remediation": [
            "Tunnel VNC exclusively through SSH or a VPN; do not expose port 5900 to public networks.",
            "Require strong authentication and replace legacy RFB with secure alternatives.",
            "Set screen lock timeouts and restrict local access rights."
        ]
    },
    6379: {
        "service": "Redis In-Memory Key-Value Store",
        "description": "In-memory data structure store used as a database, cache, message broker, and streaming engine.",
        "risk": "Critical",
        "risk_explanation": "Designed for trusted internal environments; unauthenticated public exposure frequently leads to complete root server compromise.",
        "exploit_vectors": [
            "Writing malicious files to disk: Attackers use Redis `CONFIG SET dir` and `CONFIG SET dbfilename` to overwrite `/root/.ssh/authorized_keys` or write cron jobs in `/var/spool/cron/crontabs/` to gain an immediate remote root shell.",
            "Writing web shells into web server document roots (`/var/www/html/`).",
            "Executing Lua sandbox escape vulnerabilities.",
            "Dumping and wiping sensitive cache and session tokens."
        ],
        "remediation": [
            "Bind Redis strictly to loopback (`bind 127.0.0.1 ::1`).",
            "Enable protected mode (`protected-mode yes`).",
            "Require a strong authentication password (`requirepass <strong-random-password>`).",
            "Rename or disable dangerous commands (`rename-command CONFIG ''`, `rename-command FLUSHALL ''`, `rename-command EVAL ''`)."
        ]
    },
    8080: {
        "service": "HTTP Alternate / Application Server",
        "description": "Common port for secondary web services, administrative panels, proxies, and application servers (Tomcat, Jenkins, etc.).",
        "risk": "High",
        "risk_explanation": "Frequently hosts administrative dashboards, CI/CD tools, or development backends with default credentials.",
        "exploit_vectors": [
            "Administrative panel access with default credentials (e.g., Apache Tomcat Manager `admin/admin`, Jenkins unauthenticated console).",
            "Arbitrary WAR file or script deployment leading to remote code execution.",
            "Exposed debugging endpoints (Spring Boot Actuator `/env`, `/heapdump` leaking database credentials and tokens).",
            "Open proxy abuse."
        ],
        "remediation": [
            "Place behind reverse proxy with HTTPS, strong authentication, and IP whitelisting.",
            "Disable or secure administrative interfaces and change all default passwords.",
            "Restrict or secure actuator/debug endpoints.",
            "Apply web application vulnerability scanning."
        ]
    },
    8443: {
        "service": "HTTPS Alternate / Secure Admin Panel",
        "description": "Encrypted alternate HTTP port frequently used for secure management consoles and application gateways.",
        "risk": "Medium",
        "risk_explanation": "Encrypted communication, but commonly hosts administrative surfaces vulnerable to credential brute forcing or unpatched software.",
        "exploit_vectors": [
            "Brute forcing administrator portal passwords.",
            "Targeting known CVEs in web management software (e.g., firewall web GUIs, hypervisor consoles).",
            "Application-level vulnerabilities in hosted APIs."
        ],
        "remediation": [
            "Restrict access to administrative IP ranges or require VPN access.",
            "Enforce Multi-Factor Authentication (MFA) on all admin portals.",
            "Keep underlying application servers updated with security patches."
        ]
    },
    9200: {
        "service": "Elasticsearch REST API",
        "description": "Distributed, RESTful search and analytics engine.",
        "risk": "Critical",
        "risk_explanation": "Default setups historically lacked authentication, leading to mass data breaches and ransomware wipes.",
        "exploit_vectors": [
            "Unauthenticated REST API access allowing attackers to dump all indexed company data, customer records, and credentials.",
            "Deleting all indices (`DELETE /_all`) for ransom extortion.",
            "Remote code execution via dynamic scripting or vulnerabilities like Log4Shell (CVE-2021-44228)."
        ],
        "remediation": [
            "Never expose port 9200 directly to the internet.",
            "Enable Elasticsearch Security features (`xpack.security.enabled: true`) with TLS and role-based access control.",
            "Bind only to internal cluster interfaces."
        ]
    },
    27017: {
        "service": "MongoDB NoSQL Database",
        "description": "Leading NoSQL document-oriented database program.",
        "risk": "Critical",
        "risk_explanation": "Default configurations without authentication have resulted in thousands of exposed databases and automated ransomware attacks.",
        "exploit_vectors": [
            "Unauthenticated connections granting full read/write privileges to all databases.",
            "Automated ransomware scripts wiping collections and leaving ransom demands.",
            "Data exfiltration of confidential customer databases.",
            "NoSQL injection vulnerabilities through poorly sanitized queries."
        ],
        "remediation": [
            "Enable authentication in `mongod.conf` (`security.authorization: enabled`).",
            "Bind MongoDB strictly to localhost (`net.bindIp: 127.0.0.1`) or private VPC subnet.",
            "Create dedicated users with minimal privileges rather than using administrative accounts.",
            "Enable TLS/SSL encryption for network traffic."
        ]
    }
}

DEFAULT_UNKNOWN_PORT = {
    "service": "Unknown / Custom Service",
    "description": "Non-standard or custom network service listening on this port.",
    "risk": "Medium",
    "risk_explanation": "Unrecognized open port expanding the host attack surface; service behavior and security controls depend on the listening daemon.",
    "exploit_vectors": [
        "Fingerprinting the underlying daemon through banner grabbing to identify unpatched software versions.",
        "Fuzzing custom protocol handlers for buffer overflows or denial-of-service vulnerabilities.",
        "Potential unauthorized backdoor, debug console, or shadow IT deployment."
    ],
    "remediation": [
        "Investigate the listening process on the host (`ss -tulpn` or `netstat -ano`).",
        "If the service is not business-critical, disable it or close the port on the firewall.",
        "If required, ensure the software is updated, authenticated, and restricted to trusted networks."
    ]
}


def get_port_security_info(port_num: int, service_name: str = "") -> dict:
    """
    Retrieve security details, risk level, theoretical exploit vectors,
    and remediation advice for a given port number and service banner.
    """
    try:
        port_int = int(port_num)
    except (ValueError, TypeError):
        port_int = -1

    if port_int in PORT_DATABASE:
        info = PORT_DATABASE[port_int].copy()
        if service_name and service_name != "unknown":
            info["detected_service"] = service_name
        return info

    # Heuristic fallback based on service name if port not directly mapped
    svc_lower = (service_name or "").lower()
    for known_port, known_data in PORT_DATABASE.items():
        if known_data["service"].lower().startswith(svc_lower) and len(svc_lower) > 2:
            custom_info = known_data.copy()
            custom_info["detected_service"] = service_name
            return custom_info

    fallback = DEFAULT_UNKNOWN_PORT.copy()
    fallback["detected_service"] = service_name or "unknown"
    return fallback
