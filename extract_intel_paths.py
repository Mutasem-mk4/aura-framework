with open("logic_finding_log.txt", "r", encoding="utf-8") as f:
    content = f.read()
    findings = content.split("-" * 50)
    for finding in findings:
        if "intel" in finding.lower():
            for line in finding.split("\n"):
                if line.startswith("content:"):
                    print(line.strip())
