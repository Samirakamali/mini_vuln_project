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

### 1. Accounts Module

Handles authentication and user management.

Features:

* Custom user model
* JWT authentication
* Activity logging
* Role-based access

Key files:

* `models.py`
* `serializers.py`
* `jwt_views.py`
* `views.py`

---

### 2. Scans Module

Responsible for asset discovery and scanning.

Features:

* Nmap integration
* Asset scanning
* Scan management commands
* Scan API endpoints

Key components:

* `nmap_utils.py`
* `views.py`
* `serializers.py`
* `management/commands/`

Available commands:

```
discover
scan_all
scan_asset
```

---

### 3. Vulnerabilities Module

Handles vulnerability analysis and audit logic.

Features:

* Audit engine
* Vulnerability tracking
* Scan result analysis

Key components:

* `audit_engine.py`
* `models.py`
* `views.py`

---

## Technology Stack

* Python 3
* Django
* Django REST Framework
* JWT Authentication
* Nmap
* Docker

---

## Project Structure

```
mini_vuln_project
│
├── accounts/        # Authentication and user management
├── scans/           # Asset discovery and scanning
├── vulns/           # Vulnerability analysis
│
├── requirements.txt
├── Dockerfile
└── README.md
```

---

# Installation

## 1. Clone the Repository

```
git clone https://github.com/yourusername/mini-vuln-scanner.git
cd mini-vuln-scanner
```

---

## 2. Create Virtual Environment

```
python -m venv venv
source venv/bin/activate
```

Windows:

```
venv\Scripts\activate
```

---

## 3. Install Dependencies

```
pip install -r requirements.txt
```

---

## 4. Install Nmap

Linux:

```
sudo apt install nmap
```

Mac:

```
brew install nmap
```

---

## 5. Run Migrations

```
python manage.py migrate
```

---

## 6. Create Superuser

```
python manage.py createsuperuser
```

---

## 7. Start Development Server

```
python manage.py runserver
```

Server will run at:

```
http://127.0.0.1:8000
```

---

# Running Scans

The project provides management commands for scanning.

## Discover Assets

```
python manage.py discover
```

## Scan All Assets

```
python manage.py scan_all
```

## Scan Single Asset

```
python manage.py scan_asset <asset_id>
```

---

# API Features

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

---

# Future Improvements

* Web dashboard
* Scheduled scanning
* CVE database integration
* Reporting system
* Severity scoring
* Automated alerts

---

# Contributing

Contributions are welcome.

Steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a pull request

---

# License

This project is licensed under the **MIT License**.

---

# Author

Security Research / Backend Development Project
Built for learning **network scanning and vulnerability analysis workflows** using Django and Nmap.
