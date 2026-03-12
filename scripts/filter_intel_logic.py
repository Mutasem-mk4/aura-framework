with open("logic_finding_log.txt", "r", encoding="utf-8") as f:
    content = f.read()
    findings = content.split("-" * 50)
    for finding in findings:
        if "intel" in finding.lower():
            print(finding)
            print("-" * 50)
