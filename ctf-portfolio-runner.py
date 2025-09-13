#!/usr/bin/env python3
"""
CTF Portfolio Runner - Python Version with Flask Web Interface
"""

import os
import sys
import subprocess
from flask import Flask, render_template_string

class CTFPortfolioRunner:
    def __init__(self):
        self.base_dir = os.getcwd()
        self.challenges = {
            1: {"name": "Web Application Security", "dir": "challenge-01-web-sqli", "script": "source-code/vulnerable_app.py"},
            2: {"name": "Cryptographic Analysis",   "dir": "challenge-02-cryptography", "script": "solution-scripts/crypto_solver.py"},
            3: {"name": "Network Traffic Analysis",  "dir": "challenge-03-network-forensics","script":"analysis-scripts/network_analyzer.py"},
            4: {"name": "Reverse Engineering",       "dir": "challenge-04-reverse-engineering","script":"malware-samples/educational_malware.py"},
            5: {"name": "OSINT Investigation",       "dir": "challenge-05-osint-investigation","script":"investigation-tools/osint_investigator.py"}
        }

    def setup_dependencies(self):
        for challenge in self.challenges.values():
            challenge_dir = challenge["dir"]
            if os.path.exists(challenge_dir):
                for root, dirs, files in os.walk(challenge_dir):
                    if "requirements.txt" in files:
                        req_file = os.path.join(root, "requirements.txt")
                        subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file], check=False)

    def get_portfolio_overview(self):
        output = "🎯 <b>CYBERSECURITY CTF PORTFOLIO</b><br><br>"
        for num, info in self.challenges.items():
            output += f"{num}) {info['name']}<br>"
        return output

# -----------------------------
# FLASK WEB INTERFACE
# -----------------------------
app = Flask(__name__)
runner = CTFPortfolioRunner()

@app.route("/")
def home():
    return render_template_string(runner.get_portfolio_overview())

# -----------------------------
# CLI VERSION
# -----------------------------
def run_cli():
    runner.print_banner = lambda: print("🎯 CYBERSECURITY CTF PORTFOLIO\n" + "="*40 + "\nProfessional-grade challenges for skill demonstration\n")
    runner.show_menu = lambda: print("\n".join([f"{num}) {info['name']}" for num, info in runner.challenges.items()]) + "\n6) Setup All Dependencies\n7) Portfolio Overview\n8) Exit\n")
    
    runner.show_portfolio_overview = lambda: print(runner.get_portfolio_overview())

    runner.run = lambda: None  # CLI loop disabled in web mode
    runner.run_cli = lambda: exec_cli(runner)

def exec_cli(runner):
    runner.print_banner()
    while True:
        runner.show_menu()
        try:
            choice = int(input("Choose an option (1-8): "))
        except ValueError:
            print("❌ Enter a valid number")
            continue

        if choice in range(1,6):
            info = runner.challenges[choice]
            full_script = os.path.join(info["dir"], info["script"])
            if os.path.exists(full_script):
                print(f"🚀 Running {info['name']} script...")
                subprocess.run([sys.executable, full_script])
            else:
                print(f"❌ Script not found: {full_script}")
        elif choice == 6:
            runner.setup_dependencies()
            print("✅ Dependencies setup complete!")
        elif choice == 7:
            print(runner.get_portfolio_overview())
        elif choice == 8:
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid selection")
        input("\nPress Enter to return to menu...")

# Run CLI if executed directly
if __name__ == "__main__":
    run_cli()
    runner.run_cli()
