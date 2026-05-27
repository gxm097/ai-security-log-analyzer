# AI-Powered Linux Log Analyzer
A local cybersecurity log analysis assistant built with Python and 
Ollama. The tool parses Linux authentication/system logs, detects SSH 
activity, account changes, file creation, suspicious processes, and 
active SSH sessions, then generates an AI-assisted SOC-style report.

## Features
- Converts Linux logs into JSONL
- Detects failed and successful SSH activity
- Tracks attempts before successful login
- Detects user creation and password changes
- Checks file creation for suspicious or newly created users
- Detects active remote SSH sessions
- Flags suspicious running processes
- Generates AI-assisted reports using Ollama

## Requirements
- Python 3
- Ollama
- A local Ollama model such as llama3

## Usage
```bash
python3 run.py

## 5. Initialize Git
```bash
git init
git add .
git commit -m "Initial AI log analyzer project"
