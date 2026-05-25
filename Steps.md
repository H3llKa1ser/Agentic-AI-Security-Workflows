     
     
    
    Cybersecurity AI Workflows – Step-by-Step Setup Guide
    Overview
    This guide walks you through setting up 8 Agentic AI Cybersecurity Workflows using 100% free and open-source tools. Each workflow includes step-by-step instructions, sample Python code, and configuration details.
    Workflows Covered:
    Automated Threat Detection & Triage
    Phishing Detection & Response
    Vulnerability Management Agent
    Pentest Assistance Agent
    Threat Intelligence Collection & Analysis
    Incident Response Orchestration
    Secure Code Review (DevSecOps)
    Compliance & Audit Automation
    Section 0 – Prerequisites & Environment Setup
    Complete this one-time setup before building any workflow. All tools below are free.
    Step 1 – Install Python 3.10+
    1.	Download from https://python.org/downloads
    2.	On Windows, tick "Add Python to PATH" during installation
    3.	Verify: python --version
    Step 2 – Install Ollama (Local LLM Engine)
    4.	Download from https://ollama.com (Windows / macOS / Linux)
    5.	Pull free AI models:
    ollama pull llama3       # Best all-rounder
    ollama pull mistral      # Fast & capable
    ollama pull codellama    # Code & security tasks
    ollama serve             # Start local server on localhost:11434
    Privacy Tip: Ollama runs 100% locally. No data is sent to external servers — essential for sensitive security data.
    Step 3 – Create Python Virtual Environment
    mkdir cybersec-ai && cd cybersec-ai
    python -m venv venv
    source venv/bin/activate        # Linux/macOS
    venv\Scripts\activate            # Windows
    Step 4 – Install Core Python Packages
    pip install langchain langchain-community langgraph
    pip install crewai
    pip install requests python-dotenv chromadb flask
    pip install openai   # Compatible with Groq free API
    Step 5 – Register Free API Keys
    Service	Website	Free Allowance
    VirusTotal	virustotal.com	4 requests/min
    AbuseIPDB	abuseipdb.com	1,000 checks/day
    AlienVault OTX	otx.alienvault.com	Unlimited feeds
    URLScan.io	urlscan.io	Free public scans
    Groq API	console.groq.com	14,400 req/day free
    MalwareBazaar	bazaar.abuse.ch	Fully free
    NVD / NIST	nvd.nist.gov	Fully free CVE API
    Step 6 – Create .env File
    VIRUSTOTAL_API_KEY=your_key_here
    ABUSEIPDB_API_KEY=your_key_here
    OTX_API_KEY=your_key_here
    GROQ_API_KEY=your_key_here
    SLACK_WEBHOOK_URL=your_webhook_here
    Step 7 – Install n8n (Workflow Automation UI)
    npm install -g n8n
    n8n start
    # Open: http://localhost:5678
    Step 8 – Install Wazuh SIEM (Docker)
    git clone https://github.com/wazuh/wazuh-docker.git
    cd wazuh-docker/single-node
    docker compose up -d
    # Dashboard: https://localhost  (admin / SecretPassword)
    Note: Wazuh requires Docker Desktop — install from https://docker.com/products/docker-desktop
    Workflow 1 – Automated Threat Detection & Triage
    Goal: Receive SIEM alerts, enrich with threat intel, classify severity, and auto-notify the SOC team.
    Stack: Wazuh SIEM → Flask API → AbuseIPDB → Ollama/LLaMA3 → Slack Webhook
    Total Cost: $0
    Step 1 – Configure Wazuh Alert Forwarding
    6.	Login to Wazuh Dashboard → Settings → Integrations
    7.	Enable Webhook integration, point to: http://localhost:8000/alert
    8.	Set minimum alert level to 7 to reduce noise
    Step 2 – Create the Alert Receiver (Flask API)
    # alert_receiver.py
    from flask import Flask, request, jsonify
    import threading
    from triage_agent import run_triage
    
    app = Flask(__name__)
    
    @app.route("/alert", methods=["POST"])
    def receive_alert():
        alert = request.json
        threading.Thread(target=run_triage, args=(alert,)).start()
        return jsonify({"status": "queued"}), 200
    
    if __name__ == "__main__":
        app.run(port=8000)
    Step 3 – Build the Triage Agent
    # triage_agent.py
    import os, requests
    from langchain_community.llms import Ollama
    from dotenv import load_dotenv
    load_dotenv()
    
    llm = Ollama(model="llama3")
    
    def check_ip(ip):
        headers = {"Key": os.getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"}
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
            headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90})
        return r.json().get("data", {})
    
    def run_triage(alert):
        src_ip  = alert.get("data", {}).get("srcip", "unknown")
        rule    = alert.get("rule", {}).get("description", "")
        level   = alert.get("rule", {}).get("level", 0)
        ip_info = check_ip(src_ip) if src_ip != "unknown" else {}
        prompt = f"""
        You are a SOC analyst. Analyze this alert:
        Rule: {rule}, Level: {level}, Source IP: {src_ip}
        Abuse Score: {ip_info.get('abuseConfidenceScore','N/A')}%
        Classify as: FALSE_POSITIVE, LOW, MEDIUM, or HIGH.
        Give a 2-sentence reason and recommended action.
        """
        verdict = llm.invoke(prompt)
        print(f"[TRIAGE] {src_ip} -> {verdict}")
        notify_slack(verdict)
    
    def notify_slack(verdict):
        webhook = os.getenv("SLACK_WEBHOOK_URL")
        requests.post(webhook, json={"text": f"Alert Triage Result:\n{verdict}"})
    Step 4 – Run & Test
    python alert_receiver.py
    # Trigger a test alert in Wazuh to verify the pipeline
    Workflow 2 – Phishing Detection & Response
    Goal: Analyze reported phishing emails, scan URLs, and auto-quarantine malicious messages.
    Stack: Gmail API → Python → VirusTotal + URLScan.io → Ollama/Mistral → Auto-response
    Total Cost: $0
    Step 1 – Install Dependencies
    pip install google-auth google-auth-oauthlib google-api-python-client beautifulsoup4
    Step 2 – Set Up Gmail API
    9.	Go to https://console.cloud.google.com → Create a project
    10.	Enable Gmail API → Create OAuth 2.0 credentials
    11.	Download credentials.json to your project folder
    # gmail_auth.py
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    
    SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
    
    def get_service():
        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
        creds = flow.run_local_server(port=0)
        return build("gmail", "v1", credentials=creds)
    Step 3 – Build Phishing Analysis Agent
    # phishing_agent.py
    import re, os, requests
    from langchain_community.llms import Ollama
    from dotenv import load_dotenv
    load_dotenv()
    
    llm = Ollama(model="mistral")
    
    def extract_urls(text):
        return re.findall(r'https?://[^\s<>"]+', text)
    
    def scan_url(url):
        headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
        r = requests.post("https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url})
        return r.json()
    
    def analyze_email(body, subject, sender):
        urls = extract_urls(body)
        vt   = [scan_url(u) for u in urls[:3]]
        prompt = f"""
        Analyze for phishing:
        Subject: {subject}, Sender: {sender}
        URLs found: {urls}
        VirusTotal results: {vt}
        Verdict: PHISHING, SPAM, or LEGITIMATE?
        """
        return llm.invoke(prompt)
    Step 4 – Auto-Quarantine Action
    def respond(verdict, email_id, service):
        if "PHISHING" in verdict.upper():
            service.users().messages().trash(userId="me", id=email_id).execute()
            print("[ACTION] Email quarantined")
        elif "SPAM" in verdict.upper():
            service.users().messages().modify(
                userId="me", id=email_id,
                body={"addLabelIds": ["SPAM"]}
            ).execute()
    Step 5 – Schedule via n8n
    12.	Open n8n at http://localhost:5678
    13.	Create workflow: Gmail Trigger (label: "Report Phishing") → Execute Command → phishing_agent.py
    14.	Add a Slack node to notify the security team with the verdict
    Workflow 3 – Vulnerability Management Agent
    Goal: Scan network for vulnerabilities, prioritize with AI using CVE data, generate remediation tickets.
    Stack: OpenVAS (free) → Python → NVD API → Ollama/LLaMA3 → JIRA Free / Email
    Total Cost: $0
    Step 1 – Install OpenVAS via Docker
    docker run -d -p 9392:9392 --name openvas \
      -e PASSWORD=admin123 \
      greenbone/community-edition
    # Web UI: https://localhost:9392  (admin / admin123)
    Step 2 – Install Python GVM Library
    pip install python-gvm
    Step 3 – Trigger Scan Programmatically
    # vuln_scanner.py
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
    
    def run_scan(target_ip):
        conn = TLSConnection(hostname="localhost", port=9392)
        with Gmp(conn, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate("admin", "admin123")
            target = gmp.create_target(name=target_ip, hosts=target_ip)
            task   = gmp.create_task(
                name=f"Scan {target_ip}",
                config_id="daba56c8-73ec-11df-a475-002264764cea",
                target_id=target.get("id"),
                scanner_id="08b69003-5fc2-4037-a479-93b440211c73"
            )
            gmp.start_task(task.get("id"))
            print(f"Scan started for {target_ip}")
    Step 4 – AI Prioritization with NVD CVE Data
    # vuln_prioritizer.py
    import requests
    from langchain_community.llms import Ollama
    
    llm = Ollama(model="llama3")
    
    def get_cvss(cve_id):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        data = requests.get(url).json()
        metrics = data["vulnerabilities"][0]["cve"]["metrics"]
        return metrics.get("cvssMetricV31",[{}])[0].get("cvssData",{}).get("baseScore",0)
    
    def prioritize(vuln_list):
        for v in vuln_list:
            score = get_cvss(v["cve_id"]) if v.get("cve_id") else 0
            prompt = f"Vuln: {v['name']}, CVSS: {score}, Host: {v['host']}. Priority: IMMEDIATE, THIS_WEEK, or THIS_MONTH?"
            print(llm.invoke(prompt))
    Step 5 – Generate Report
    def generate_report(vulns):
        with open("vuln_report.md", "w") as f:
            f.write("# Vulnerability Report\n\n")
            for v in vulns:
                f.write(f"## {v['name']}\n- CVSS: {v['cvss']}\n- Host: {v['host']}\n\n")
        print("Report saved!")
    Workflow 4 – Pentest Assistance Agent
    LEGAL WARNING: Only use these tools on systems you OWN or have WRITTEN PERMISSION to test. Unauthorized scanning is illegal.
    Goal: Automate recon, attack surface mapping, and professional pentest report generation.
    Stack: Nmap + Subfinder + theHarvester → LangChain → Shodan API → Ollama → Markdown Report
    Total Cost: $0
    Step 1 – Install Recon Tools
    # Nmap
    sudo apt install nmap           # Linux
    winget install nmap             # Windows
    
    # Python tools
    pip install python-nmap theHarvester
    
    # Subfinder (requires Go installed)
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    Step 2 – Build the Recon Agent
    # recon_agent.py
    import nmap, subprocess, json
    from langchain_community.llms import Ollama
    
    llm = Ollama(model="mistral")
    
    def nmap_scan(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV -sC --top-ports 1000")
        return nm[target] if target in nm.all_hosts() else {}
    
    def subfinder(domain):
        result = subprocess.run(["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True)
        return result.stdout.strip().split("\n")
    
    def analyze(nmap_data, subdomains, target):
        prompt = f"""
        Pentest target: {target}
        Subdomains discovered: {subdomains[:10]}
        Open ports & services: {json.dumps(nmap_data)[:1500]}
        List top 5 attack vectors with MITRE ATT&CK technique IDs.
        """
        return llm.invoke(prompt)
    Step 3 – Auto-Generate Pentest Report
    def report(target, subdomains, nmap_data, analysis):
        import datetime
        content  = f"# Pentest Report\n**Target:** {target}\n"
        content += f"**Date:** {datetime.date.today()}\n\n"
        content += f"## Attack Surface Analysis\n{analysis}\n\n"
        content += f"## Subdomains ({len(subdomains)})\n"
        content += "\n".join(f"- {s}" for s in subdomains)
        with open("pentest_report.md", "w") as f:
            f.write(content)
        print("Pentest report saved!")
    Workflow 5 – Threat Intelligence Collection & Analysis
    Goal: Continuously collect IOCs from free threat feeds, correlate, and trigger defensive actions.
    Stack: AlienVault OTX + ThreatFox + MalwareBazaar → n8n → OpenCTI → Ollama/LLaMA3
    Total Cost: $0
    Step 1 – Install OpenCTI (Free Threat Intel Platform)
    git clone https://github.com/OpenCTI-Platform/docker.git openCTI
    cd openCTI
    cp .env.sample .env
    docker compose up -d
    # Access: http://localhost:8080
    Step 2 – Pull IOCs from Free Feeds
    # threat_feeds.py
    import requests, os
    from dotenv import load_dotenv
    load_dotenv()
    
    def get_otx_iocs():
        headers = {"X-OTX-API-KEY": os.getenv("OTX_API_KEY")}
        r = requests.get("https://otx.alienvault.com/api/v1/indicators/export",
            headers=headers, params={"type": "IPv4", "limit": 100})
        return r.json().get("results", [])
    
    def get_threatfox():
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1})
        return r.json().get("data", [])
    
    def get_malwarebazaar():
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"})
        return r.json().get("data", [])
    Step 3 – AI IOC Relevance Analysis
    # ioc_analyzer.py
    from langchain_community.llms import Ollama
    
    llm = Ollama(model="llama3")
    
    def analyze(iocs, org_context):
        prompt = f"""
        You are a CTI analyst.
        Organization: {org_context}
        Recent IOCs: {iocs[:20]}
        Which are most relevant? Map to MITRE ATT&CK. Suggest defensive actions.
        """
        return llm.invoke(prompt)
    
    print(analyze(
        iocs=get_threatfox(),
        org_context="Financial company on AWS/Azure with Windows Active Directory"
    ))
    Step 4 – n8n Continuous Monitoring Workflow
    15.	Open n8n → Create new workflow
    16.	Add: Cron node (every 6 hours) → HTTP Request (ThreatFox API)
    17.	Add: Code node to run IOC analysis
    18.	Add: IF node → high relevance score → Slack alert + firewall block rule
    Workflow 6 – Incident Response Orchestration
    Goal: AI-assisted end-to-end IR: identification, containment, eradication, recovery, and reporting.
    Stack: Wazuh → CrewAI Multi-Agent → Ollama/LLaMA3 → TheHive (free IR platform) → Slack
    Total Cost: $0
    Step 1 – Install TheHive (Free IR Platform)
    docker run -d --name thehive -p 9000:9000 strangebee/thehive:latest
    # Access: http://localhost:9000
    # Default login: admin@thehive.local / secret
    Step 2 – Create Multi-Agent IR Crew
    # ir_crew.py
    from crewai import Agent, Task, Crew
    from langchain_community.llms import Ollama
    
    llm = Ollama(model="llama3")
    
    identifier = Agent(
        role="Incident Identifier",
        goal="Identify and classify security incidents",
        backstory="Senior SOC analyst with 10 years experience",
        llm=llm
    )
    containment = Agent(
        role="Containment Specialist",
        goal="Contain threats and prevent lateral movement",
        backstory="IR specialist focused on rapid containment",
        llm=llm
    )
    reporter = Agent(
        role="IR Reporter",
        goal="Document incidents and write full RCA reports",
        backstory="Technical writer and compliance expert",
        llm=llm
    )
    Step 3 – Define Tasks & Run the Crew
    def run_ir(incident_data):
        t1 = Task(
            description=f"Analyze: {incident_data}. Build timeline, identify affected assets.",
            agent=identifier
        )
        t2 = Task(
            description="List containment steps per affected system.",
            agent=containment
        )
        t3 = Task(
            description="Write full IR report: summary, timeline, impact, RCA, lessons learned.",
            agent=reporter
        )
        crew = Crew(
            agents=[identifier, containment, reporter],
            tasks=[t1, t2, t3],
            verbose=True
        )
        return crew.kickoff()
    
    # Usage:
    result = run_ir("Ransomware detected on 3 workstations, AD accounts locked")
    print(result)
    Workflow 7 – Secure Code Review Agent (DevSecOps)
    Goal: Automatically scan PRs for security vulnerabilities and suggest fixes before production.
    Stack: GitHub Actions (free 2000 min/month) → Semgrep + Gitleaks + Bandit → Groq API/CodeLlama → PR Comments
    Total Cost: $0
    Step 1 – Install Security Scanners
    pip install semgrep bandit
    
    # Gitleaks – download from:
    # https://github.com/gitleaks/gitleaks/releases
    # Linux:
    wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
    tar -xzf gitleaks_linux_x64.tar.gz && sudo mv gitleaks /usr/local/bin/
    Step 2 – Create GitHub Actions Workflow
    # .github/workflows/security.yml
    name: AI Security Code Review
    on:
      pull_request:
        branches: [main]
    
    jobs:
      security:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
    
          - name: Semgrep SAST
            uses: semgrep/semgrep-action@v1
            with:
              config: p/owasp-top-ten p/secrets
    
          - name: Gitleaks Secret Scan
            uses: gitleaks/gitleaks-action@v2
    
          - name: Bandit Python Scan
            run: |
              pip install bandit
              bandit -r . -f json -o results.json || true
    
          - name: AI Review
            run: python ai_reviewer.py
            env:
              GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}
    Step 3 – AI Code Review Script (Groq Free API)
    # ai_reviewer.py
    import json, os
    from openai import OpenAI
    
    client = OpenAI(
        api_key=os.getenv("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1"
    )
    
    def review(results_file):
        with open(results_file) as f:
            findings = json.load(f)
        for issue in findings.get("results", [])[:10]:
            prompt = f"""
            Security finding:
            Issue: {issue['issue_text']}
            Code: {issue['code']}
            File: {issue['filename']}:{issue['line_number']}
            Provide: 1) Risk explanation 2) Fixed code 3) CWE reference
            """
            r = client.chat.completions.create(
                model="llama3-70b-8192",
                messages=[{"role": "user", "content": prompt}]
            )
            print(r.choices[0].message.content)
    
    review("results.json")
    Step 4 – Add GROQ_API_KEY as GitHub Secret
    19.	Go to GitHub Repo → Settings → Secrets and variables → Actions
    20.	Click New repository secret → Name: GROQ_API_KEY → Paste your key
    Workflow 8 – Compliance & Audit Automation
    Goal: Continuously monitor compliance against frameworks (ISO 27001, SOC2, GDPR, NIST) and auto-generate evidence.
    Stack: Python + LangChain → Ollama/LLaMA3 → AWS/Azure Free APIs → Markdown Reports
    Total Cost: $0
    Step 1 – Install Dependencies
    pip install langchain langgraph boto3 azure-identity reportlab
    Step 2 – Define Compliance Controls
    # controls.py
    CONTROLS = {
        "CC1": {"name": "Password Policy", "framework": "ISO 27001",
                "check": "Verify password complexity is enforced"},
        "CC2": {"name": "MFA Enforcement", "framework": "SOC2",
                "check": "All admin accounts must have MFA enabled"},
        "CC3": {"name": "Encryption at Rest", "framework": "GDPR",
                "check": "All storage buckets and databases must be encrypted"},
        "CC4": {"name": "Access Reviews", "framework": "ISO 27001",
                "check": "Quarterly user access reviews must be completed"},
    }
    Step 3 – Automated Evidence Collection
    # evidence.py
    import boto3
    
    def check_s3_encryption():
        s3 = boto3.client("s3")
        results = []
        for b in s3.list_buckets()["Buckets"]:
            try:
                s3.get_bucket_encryption(Bucket=b["Name"])
                results.append({"bucket": b["Name"], "encrypted": True})
            except:
                results.append({"bucket": b["Name"], "encrypted": False})
        return results
    
    def check_iam_mfa():
        iam = boto3.client("iam")
        results = []
        for user in iam.list_users()["Users"]:
            mfa = iam.list_mfa_devices(UserName=user["UserName"])
            results.append({"user": user["UserName"], "mfa": len(mfa["MFADevices"]) > 0})
        return results
    Step 4 – AI Gap Analysis & Report Generation
    # compliance_agent.py
    from langchain_community.llms import Ollama
    
    llm = Ollama(model="llama3")
    
    def gap_analysis(control, evidence):
        prompt = f"""
        Compliance Control: {control['name']} ({control['framework']})
        Requirement: {control['check']}
        Evidence collected: {evidence}
        Status: COMPLIANT, PARTIAL, or NON_COMPLIANT?
        List specific gaps and remediation steps.
        """
        return llm.invoke(prompt)
    
    def generate_report(results):
        with open("compliance_report.md", "w") as f:
            f.write("# Compliance Assessment Report\n\n")
            for cid, data in results.items():
                f.write(f"## {cid}: {data['control']}\n")
                f.write(f"**Status:** {data['status']}\n\n{data['analysis']}\n\n---\n")
        print("Compliance report saved!")
    Troubleshooting & Pro Tips
    Common Issues & Fixes
    Issue	Cause	Fix
    Ollama not responding	Server not started	Run: `ollama serve`
    VirusTotal rate limit	Free = 4 req/min	Add `time.sleep(15)` between requests
    n8n not opening	Port conflict	Use: `n8n start --port 5679`
    Docker crash	Low memory	Increase Docker memory to 8GB+
    Wazuh agents not connecting	Firewall blocking	Open ports 1514/UDP and 1515/TCP
    GitHub Actions failing	Missing secrets	Add keys in repo Settings > Secrets
    LangChain import error	Outdated package	`pip install --upgrade langchain langchain-community`
    CrewAI loops forever	No iteration limit	Add `max_iter=5` to `Agent()` constructor
    OpenVAS not starting	Docker not running	Run: `docker start openvas`
    Gmail API access denied	Wrong OAuth scope	Use `gmail.modify` scope and re-authenticate
    Pro Tips
    21.	Privacy First: Always use local Ollama models for sensitive security data. Never send logs or IPs to external LLM APIs.
    22.	Speed: Use Groq API free tier when you need fast responses and data is non-sensitive.
    23.	Memory: Use ChromaDB for vector storage of threat intel (enables AI to remember past incidents).
    24.	Schedule: Use n8n Cron nodes to run workflows automatically — avoid manual script execution.
    25.	Audit Logs: Log all agent decisions to files for audit trails and future playbook improvement.
    26.	Isolation: Run scanning tools inside a dedicated VM or Docker network for safety.
    27.	API Keys: Store all keys in .env files only. Never hardcode secrets in scripts.
    28.	Start Small: Build and test 1 workflow fully before moving to the next.
    Free Learning Resources
    Resource	Type	URL
    LangChain Docs	Documentation	python.langchain.com
    CrewAI Docs	Documentation	docs.crewai.com
    Wazuh Docs	Documentation	documentation.wazuh.com
    MITRE ATT&CK	Framework	attack.mitre.org
    n8n Community	Forum	community.n8n.io
    Hack The Box	Practice Labs	hackthebox.com
    TryHackMe	Practice Labs	tryhackme.com
    OWASP Top 10	Security Guide	owasp.org/Top10
    Groq Playground	Free LLM API	console.groq.com
    Ollama Library	Local LLMs	ollama.com/library
    
