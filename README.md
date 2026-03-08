# 🌌 Aura: The Apex Predator (v19.5 Singularity Edition)
# Aura v25.0 — The Omni-Sovereign Bug Bounty Framework 🚀

**Aura** is the apex predator of security automation. A next-generation, autonomous, AI-driven framework designed to dominate the bug bounty battlefield through sentient logic and hyper-accelerated exploitation.

## 🛠️ Instant Installation

You can now install Aura globally from anywhere:

```bash
pip install aura-cli
```

## 🚀 Speed-of-Light Usage

Run your first mission with zero configuration:

```bash
aura example.com
```

## 🚀 Key Innovations

### 🧠 The Sentient Brain (AI Core)
*   **Business Logic Breaker**: Bypasses traditional IDOR controls, manipulates shopping carts, and skips MFA flows.
*   **Genetic Payload Mutation**: WAF blocking you? Aura dynamically rewrites its exploits (XSS, SQLi, SSRF) utilizing AI to bypass rules.
*   **Contextual Impact Scoring**: Dynamically aligns findings with real-world financial risk, calculating CVSS and potential bounty payouts.

### ⚡ Turbine Architecture (Hyper-Concurrency)
*   **Native Asyncio Scaling**: Processes hundreds of URLs simultaneously via non-blocking semaphores.
*   **WAF Caching Engine**: Drastically cuts scan time by caching WAF signatures at the domain level, avoiding redundant trigger checks.
*   **Parallelized Vulnerability Probing**: Independent engines (HostHeader, Deserialization, OpenRedirect, FileUpload) execute concurrently for blazing-fast audits.
*   **0.5s Fixed Backoff**: Brutally efficient WAF evasion pacing.

### 🕵️‍♂️ The Phantom Suite (Deep Attack Vectors)
Aura is equipped with 31 distinct phases of automated intrusion, including:
1.  **Nebula Ghost**: SSRF pivoting to internal AWS/GCP/Azure metadata services.
2.  **GraphQL Reaper**: Introspection mining, batch amplification, and query injection.
3.  **DOM Hunter**: Headless Chromium instance hunting for Blind DOM XSS.
4.  **Shadow Swarm Orchestrator**: Ephemeral IP rotation built-in.
5.  **Siege Escalation**: Race conditions, HTTP Request Smuggling, and SSTI probes.

## 📦 Installation

Aura is a **Private, Confidential Tool** and is not available on any public repository.
To install Aura globally on your system so you can run `aura` from anywhere:

```bash
# Inside the Aura directory:
pip install -e .
```
*Requires Python 3.10+*

## ⚙️ Usage

Aura operates through an intuitive, lethal Command Line Interface.

### 1. The Zenith Protocol (Autonomous Bug Bounty)
Unleash the full 31-phase attack matrix against a domain.

```bash
aura auto "target.com"
```
*   **What it does:** Subdomain enumeration, port scanning, WAF bypassing, deep spidering, credential dumping, vulnerability exploitation, and report generation.

### 2. Fast Reconnaissance (Stealth Mode)
Run a rapid, completely passive discovery phase.

```bash
aura auto "target.com" --fast
```

### 3. Targeted Module Execution
Deploy specific operational engines on demand.

```bash
# Extract and verify all endpoints from JavaScript files
aura js "https://target.com"

# Hunt for exposed Cloud/AWS credentials
aura cloud "https://target.com"

# Crawl the Wayback Machine for hidden legacy parameters
aura wayback "target.com"

# Attempt Subdomain Takeovers
aura takeover "target.com"
```

### 4. Profit Engine (Automated Reporting)
After a successful run, compile all verified vulnerabilities into a professional Markdown report ready for submission to HackerOne or Bugcrowd.

```bash
aura profit intel
```

## 🛡️ Required Configuration

Aura integrates with various third-party APIs for maximum intelligence gathering. Export these keys in your environment:

```bash
export SHODAN_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export OTX_API_KEY="your_key"
export SECURITYTRAILS_API_KEY="your_key"
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"
export GREYNOISE_API_KEY="your_key"
# Required for the AI Brain:
export GEMINI_API_KEY="your_google_ai_key" 
```

## ⚠️ Disclaimer

Aura is an extremely potent offensive security tool. It is intended strictly for authorized security auditing, bug bounty hunting, and defensive research. Any illicit usage or deployment against unauthorized targets is strictly prohibited. The developers accept no liability for the misuse of this tool.

## 🌌 The Future is Sovereign. The Future is Aura.
