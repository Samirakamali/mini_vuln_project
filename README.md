# Mini Vulnerability Scanner API

A lightweight **Django REST API–based vulnerability scanning platform** designed for discovering assets, scanning them using Nmap, and auditing potential vulnerabilities.
This project demonstrates a modular architecture for **asset discovery, scanning, and vulnerability auditing** with authentication and activity logging.

---

## Overview

Mini Vulnerability Scanner is a backend service that allows users to:

* Discover network assets
* Scan assets for open ports and services
* Perform vulnerability audits
* Manage users and authentication
* Track scan activities and results

The system is built with **Django**, **Django REST Framework**, and integrates **Nmap** for network scanning.

---

## Architecture

The project is divided into three main modules:

```
accounts/
scans/
vulns/
```

## Technology Stack

* Python 3
* Django
* Django REST Framework
* JWT Authentication
* Nmap
* Docker

---

### Authentication

JWT-based authentication system.

Example endpoints:

```
POST /api/login/
POST /api/register/
```

---

### Asset Scanning

```
GET /api/scans/
POST /api/scans/
```

---

### Vulnerability Audits

```
GET /api/vulns/
POST /api/vulns/audit/
```

---

# Docker Support

Build container:

```
docker build -t mini-vuln-scanner .
```

Run container:

```
docker run -p 8000:8000 mini-vuln-scanner
```

---

# Security Notice

This project is intended for:

* Educational purposes
* Security research
* Controlled environments

Do **not** use this scanner on networks you do not own or have explicit permission to test.


