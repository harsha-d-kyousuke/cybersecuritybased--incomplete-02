# 🛡️ Cyber Attack Simulator

![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-DB-336791?logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

A **professional-grade cybersecurity attack simulator** that allows users to run controlled attack scenarios (SQL Injection, XSS, CSRF, Brute Force, Directory Traversal, and more) against a **deliberately vulnerable test app**.  
Generates **AI-assisted vulnerability reports** with remediation guidance.  

⚠️ **Disclaimer:** This tool is for **educational and research use only**. Do not use on real-world systems without explicit permission.  

---

## 🚀 Features

- **User Management**
  - Signup/Login with JWT authentication  
  - Role-based access control (Admin / User)  

- **Attack Scenarios**
  - SQL Injection  
  - Cross-Site Scripting (XSS)  
  - CSRF (Cross-Site Request Forgery)  
  - Brute Force  
  - Directory Traversal  
  - File Upload Exploit (bonus)  

- **Execution Engine**
  - Payload injection & response capture  
  - Real-time attack execution logs  

- **Reports**
  - Vulnerability summary with severity (CVSS-style scoring)  
  - AI-generated human-readable fixes  
  - Exportable **PDF reports**  

- **Dashboard**
  - Past simulations overview  
  - Graphs & statistics  
  - Logs with timestamps  

- **Bonus**
  - CI/CD with GitHub Actions  
  - AI Chatbot Assistant inside dashboard  

---

## 📂 Project Structure

cyber-attack-simulator/
│── backend/
│ ├── main.py # FastAPI entry
│ ├── attacks/
│ │ ├── sql_injection.py
│ │ ├── xss.py
│ │ ├── csrf.py
│ │ ├── brute_force.py
│ │ └── traversal.py
│ ├── database/
│ │ └── models.py
│ ├── reports/
│ │ └── report_generator.py
│ └── ai/
│ └── fix_recommender.py
│
│── frontend/
│ ├── src/
│ │ ├── pages/
│ │ ├── components/
│ │ └── App.jsx
│
│── vulnerable-app/ # Sample Flask app with intentional flaws
│── tests/ # Unit & integration tests
│── docker-compose.yml
│── README.md

yaml
Copy code

---

## 🛠 Tech Stack

- **Backend:** Python, FastAPI  
- **Frontend:** React + TailwindCSS  
- **Database:** PostgreSQL  
- **Reporting:** PDF reports with ReportLab/WeasyPrint  
- **AI Layer:** LLM-based remediation recommender (OpenAI/HuggingFace)  
- **Deployment:** Docker + Docker Compose (cloud-ready: AWS/GCP/Azure)  

---

## 🔧 Getting Started

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-username>/cyber-attack-simulator.git
cd cyber-attack-simulator
2️⃣ Setup environment
bash
Copy code
# Backend
cd backend
pip install -r requirements.txt

# Frontend
cd frontend
npm install
3️⃣ Run with Docker
bash
Copy code
docker-compose up --build
4️⃣ Access
Backend API: http://localhost:8000

Frontend Dashboard: http://localhost:3000

Vulnerable Test App: http://localhost:5000

📊 Example Simulation
Attack: SQL Injection

Payload: ' OR 1=1 --

Report Output:

vbnet
Copy code
Vulnerability: SQL Injection
Severity: High
Description: The payload bypassed authentication by altering SQL query.
Fix: Use parameterized queries + input validation.
📖 Roadmap
 Add more attack modules (e.g., SSRF, RCE)

 Multi-user collaboration on reports

 Cloud-hosted demo version

 Integration with security scanners (OWASP ZAP, Burp API)

⚠️ Disclaimer
This project is for educational and research use only.
Running attack simulations against systems without explicit authorization is illegal.

