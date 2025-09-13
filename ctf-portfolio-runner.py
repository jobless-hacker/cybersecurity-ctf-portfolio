#!/usr/bin/env python3
"""
CTF Portfolio Runner - Hybrid Version
Works as both CLI (menu-based) and Web (Flask app).
"""

import os
import sys
import subprocess

# ---------------------------
# CLI RUNNER CLASS
# ---------------------------
class CTFPortfolioRunner:
    def __init__(self):
        # Save portfolio root directory
        self.base_dir = os.getcwd()
        self.challenges = {
            1: {"name": "Web Application Security", "dir": "challenge-01-web-sqli", "script": "source-code/vulnerable_app.py"},
            2: {"name": "Cryptographic Analysis",   "dir": "challenge-02-cryptography",   "script": "solution-scripts/crypto_solver.py"},
            3: {"name": "Network Traffic Analysis", "dir": "challenge-03-network-forensics", "script":"analysis-scripts/network_analyzer.py"},
            4: {"name": "Reverse Engineering",      "dir": "challenge-04-reverse-engineering", "script":"malware-samples/educational_malware.py"},
            5: {"name": "OSINT Investigation",      "dir": "challenge-05-osint-investigation", "script":"investigation-tools/osint_investigator.py"}
        }

    def print_banner(self):
        print("🎯 CYBERSECURITY CTF PORTFOLIO")
        print("=" * 40)
        print("Professional-grade challenges for skill demonstration")
        print()

    def show_menu(self):
        print("📋 AVAILABLE CHALLENGES")
        print("=" * 25)
        for num, info in self.challenges.items():
            print(f"{num}) {info['name']}")
        print("6) Setup All Dependencies")
        print("7) Portfolio Overview")
        print("8) Exit")
        print()

    def setup_dependencies(self):
        print("🔧 Setting up dependencies...")
        for challenge in self.challenges.values():
            challenge_dir = challenge["dir"]
            if os.path.exists(challenge_dir):
                print(f"Setting up {challenge_dir}...")
                for root, dirs, files in os.walk(challenge_dir):
                    if "requirements.txt" in files:
                        req_file = os.path.join(root, "requirements.txt")
                        try:
                            subprocess.run(
                                [sys.executable, "-m", "pip", "install", "-r", req_file],
                                check=True, stdout=subprocess.DEVNULL
                            )
                            print(f"✅ Installed: {req_file}")
                        except subprocess.CalledProcessError:
                            print(f"⚠️ Could not install: {req_file}")
        print("✅ Dependency setup complete!")

    def run_challenge(self, choice):
        info = self.challenges[choice]
        challenge_dir = info["dir"]
        script_path = info["script"]
        full_script = os.path.join(challenge_dir, script_path)

        if not os.path.exists(full_script):
            print(f"❌ Script not found: {full_script}")
            return

        print(f"🚀 Starting {info['name']}...")

        if choice == 1:
            print("🌐 Launching web application at http://localhost:5000 (Ctrl+C to stop)")

        original_dir = os.getcwd()
        if choice == 2:
            os.chdir(os.path.join(self.base_dir, challenge_dir, "solution-scripts"))
            run_script = "crypto_solver.py"
        else:
            os.chdir(os.path.join(self.base_dir, challenge_dir))
            run_script = script_path

        try:
            subprocess.run([sys.executable, run_script])
        except Exception as e:
            print(f"❌ Error running challenge: {e}")

        os.chdir(self.base_dir)

    def show_portfolio_overview(self):
        overview_file = "ctf-portfolio-master.md"
        if os.path.exists(overview_file):
            with open(overview_file, 'r', encoding='utf-8') as f:
                print(f.read()[:2000])
                print("\n... (truncated)")
                print(f"\n📄 See full overview in {overview_file}")
        else:
            print("📊 PORTFOLIO OVERVIEW")
            print("=" * 25)
            print("5 Professional challenges ready to run")

    def run(self):
        self.print_banner()
        while True:
            self.show_menu()
            try:
                choice = int(input("Choose an option (1-8): "))
            except ValueError:
                print("❌ Enter a valid number")
                continue

            if choice in range(1,6):
                self.run_challenge(choice)
            elif choice == 6:
                self.setup_dependencies()
            elif choice == 7:
                self.show_portfolio_overview()
            elif choice == 8:
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid selection")

            input("\nPress Enter to return to menu...")


# ---------------------------
# FLASK WEB VERSION
# ---------------------------
def run_web():
    from flask import Flask, render_template_string

    app = Flask(__name__)
    runner = CTFPortfolioRunner()

    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTF Portfolio</title>
        <style>
            body { font-family: Arial, sans-serif; background: #111; color: #eee; text-align: center; }
            .container { margin-top: 50px; }
            a { color: #0f0; text-decoration: none; display: block; margin: 10px; }
            a:hover { color: #ff0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 Cybersecurity CTF Portfolio</h1>
            <p>Choose a challenge to explore</p>
            <ul style="list-style:none;">
                {% for num, info in challenges.items() %}
                <li><a href="/challenge/{{num}}">{{num}}) {{info['name']}}</a></li>
                {% endfor %}
            </ul>
            <a href="/overview">📊 Portfolio Overview</a>
        </div>
    </body>
    </html>
    """

    @app.route("/")
    def home():
        return render_template_string(HTML_TEMPLATE, challenges=runner.challenges)

    @app.route("/overview")
    def overview():
        return "<h2>📊 Portfolio Overview</h2><p>5 Professional challenges ready to run</p>"

    @app.route("/challenge/<int:num>")
    def challenge(num):
        if num not in runner.challenges:
            return "❌ Invalid challenge"
        return f"<h2>🚀 {runner.challenges[num]['name']}</h2><p>(Runs locally, not in web sandbox)</p>"

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))


# ---------------------------
# MAIN ENTRY
# ---------------------------
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "web":
        run_web()
    else:
        CTFPortfolioRunner().run()
