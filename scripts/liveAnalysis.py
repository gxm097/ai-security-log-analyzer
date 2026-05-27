import subprocess

steps = [
    ("Detect SSH activity", ["python3", "susAnalyzer.py"]),
    ("Check account risk activity", ["python3", "accountRiskCheck.py"]),
    ("Check file creation activity", ["python3", "fileCreationCheck.py"]),
    ("Check active SSH sessions", ["python3", "activeSessionCheck.py"]),
    ("Generate AI analysis report", ["python3", "jsonlLogAnalyzer.py"]),
]

for name, command in steps:
    print(f"\n=== {name} ===")
    result = subprocess.run(command)

    if result.returncode != 0:
        print(f"Step failed: {name}")
        break
else:
    print("\nLive analysis complete.")