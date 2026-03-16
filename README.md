# 🛡️ Aura: The Sentient Offensive Engine

Aura is an autonomous security auditing pipeline that uses AI-driven strategic modeling to discover and weaponize complex vulnerabilities.

## 🚀 Reproducible Testing Instructions

To test Aura against a target like juice-shop (the gold standard for test targets):

### 1. Prerequisites
- Python 3.10+
- Go 1.19+ (For Nexus Core)
- Google Cloud Project with Vertex AI enabled (for the Sentient Brain)

### 2. Installation
```powershell
# Clone the repository
git clone https://github.com/mutasem-mk4/aura-core.git
cd aura-core

# Install dependencies
pip install -r requirements.txt
```

### 3. Run a Scan
To run the automated pipeline in "Clinic" mode (educational/beginner mode):
```powershell
python aura.py juice-shop.herokuapp.com --auto --clinic
```

### 4. Verify Results
- Check `reports/` for the final JSON/Markdown vulnerability report.
- Check `pocs/` for the automatically synthesized Python exploitation scripts.
- Check the terminal for the interactive **Omega Protocol** logs.

## 🏗️ Architecture
Aura follows a unique **Hybrid Brain-Core** architecture:
- **Python OMEGA Brain:** Handles strategic decision making, stateful fuzzing logic, and PoC synthesis.
- **Go NEXUS Core:** Provides ultra-fast, raw networking capabilities for high-concurrency scanning.
- **Google Vertex AI:** Powers the "Sentient Mind" for analyzing target responses and predicting attack paths.
