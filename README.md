# 🔐 SecureVault

## 📄 Description
**SecureVault** is a full-stack Django-based password manager built with a modern **glassmorphic UI**. It offers:

- 🔐 Encrypted credential storage (AES)
- 👁️‍🗨️ Real-time activity logging
- 📱 Multi-factor authentication (TOTP via Google Authenticator)
- ✅ Strong password validation with live feedback
- 🧠 Custom registration form with rule checklist, strength meter, and toggles

All user actions are securely tracked with time-adjusted activity logs. Sessions are protected, and logout warnings are displayed if left unattended.

---

## 🚀 Features

- 🔑 AES-encrypted password storage
- 📲 Two-Factor Authentication (TOTP via Google Authenticator)
- 🔁 Secure password reset with 2FA enforcement
- 👁️ Password show/hide toggle with strength meter
- 📜 Strong password validation with enforced rules
- 📊 Real-time activity logs (device, IP, timestamp)
- 🌐 Timestamps rendered in the user's local timezone
- 🎨 Glassmorphic modern UI built with Bootstrap 5

---


## 🧠 Skills Used

### 🔐 Cybersecurity
- AES encryption, MFA, session control
- Password policy enforcement
- 2FA & reset flow security

### ⚙️ Backend
- Django (Custom authentication, forms, signal-based activity logging)
- Python

### 🎨 Frontend
- HTML, CSS, Bootstrap 5
- JavaScript (live validation, local time rendering)

### 🗃️ Database
- MySQL (via SQL Workbench) with encrypted fields  
> ℹ️ SQLite was not used — replaced by production-ready MySQL integration

### 📚 Standards & Guidelines
- NIST Password Guidelines  
- ISO 27001 Concepts (for access/logging governance)

---

## 🧰 Technologies Used

| Category       | Stack                                      |
|----------------|---------------------------------------------|
| 🔧 Framework   | Django 4.x (Python 3.9+)                    |
| 💾 Database    | MySQL (configured via SQL Workbench)        |
| 🔐 Security    | AES, TOTP, CSRF, Session hardening          |
| 🌐 Frontend    | HTML5, CSS3, Bootstrap 5, Glassmorphism UI  |
| 🧪 Tools       | PyOTP, Cryptography, user_agents, Signals   |

---

## 📁 Project Structure

```
SecureVault/
├── backend/
│   ├── manage.py
│   ├── scripts/                    # 🔐 Optional utilities
│   │   ├── backup.sh              # Backup script (shell)
│   │   └── firewall.ps1           # Windows firewall script (PowerShell)
│   ├── securevault_backend/       # 🧠 Django settings + core routing
│   │   ├── __init__.py
│   │   ├── asgi.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   ├── static/                    # 🎨 CSS & frontend styles
│   │   └── style.css
│   ├── templates/                 # 🖼️ Shared HTML templates
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── register.html
│   │   ├── dashboard.html
│   │   ├── activity_log.html
│   │   ├── home.html
│   │   └── ...
│   └── vaultcore/                 # 🔐 Main application logic
│       ├── __init__.py
│       ├── admin.py
│       ├── apps.py
│       ├── forms.py
│       ├── models.py
│       ├── signals.py
│       ├── tests.py
│       ├── urls.py
│       ├── views.py
│       ├── utils/                 # Reusable functions/helpers
│       ├── migrations/
│       └── templates/vaultcore/   # 🔐 Custom 2FA + Reset flows
│           ├── forgot_password.html
│           ├── enter_secondary.html
│           ├── setup_2fa.html
│           ├── setup_2fa_reset.html
│           ├── verify_token.html
│           ├── verify_existing_otp.html
│           └── ...
├── database/                      # 🗄️ MySQL setup scripts
│   ├── init.sql
│   └── securevault_db_setup.sql
├── venv/                          # ⚙️ Virtual environment (excluded)
├── .gitignore
└── README.md

```



---

## ⚙️ Installation Guide

### 🔧 Prerequisites

- Python 3.9+
- Django 4+
- Git installed
- Virtual environment (recommended)

---

### 🛠️ Steps to Run Locally

```bash
# 1. Clone the repo
git clone https://github.com/YOUR-USERNAME/SecureVault.git
cd SecureVault/backend

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate     # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install django
pip install pyotp cryptography user-agents

# 4. Run migrations
python manage.py migrate

# 5. Create superuser (optional)
python manage.py createsuperuser

# 6. Start the development server
python manage.py runserver

```
### 🔐 Password Strength Requirements

Passwords must:

- Have at least **12 characters**
- Contain at least:
  - ✅ 1 uppercase letter  
  - ✅ 1 lowercase letter  
  - ✅ 1 number  
  - ✅ 1 special character (`@`, `#`, `$`, etc.)

> A strength meter and rule checklist are shown on the registration page.

---

### 👨‍💻 Developer

**Chirag Bhaveshkumar Soni**  
🎓 *MS in Cybersecurity with CyberDefence Concentration – Wright State University*  
💼 *Django, Cybersecurity, Secure Systems*  
🔗 [LinkedIn](https://www.linkedin.com/in/cbsoni) • [GitHub](https://github.com/chiragbsoni)


