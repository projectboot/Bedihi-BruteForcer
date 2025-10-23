# Bedihi — AI Based Brute-Force Tool

**Bedihi** is a GUI wrapper around an AI-assisted login form analyzer and a bruteforce testing engine. It was developed as a research / red-team lab tool to help security researchers analyze login form structures, collect selectors, and run controlled bruteforce experiments **only** against systems you own or explicitly have written permission to test.

[![App GUI](https://github.com/projectboot/Bedihi-BruteForcer/blob/main/gui.png?raw=true)](https://github.com/projectboot/Bedihi-BruteForcer/blob/main/gui.png)

## Features
- Runs locally / offline.
- Load URL, username, and password lists in a simple window.
- Two-step flow: examine the site first, then run attempts.
- Tries to find the login fields automatically.
- Opens a browser in background to fill and submit forms.
- Skips any site that shows a CAPTCHA.
- Only performs full username×password brute-force attempts.
- Stops testing a site once valid credentials are found.
- Detects likely success by page changes or common words.
- Saves analysis and attempt results to a local database.
- Run button is disabled while the process runs. 

## Installation
For Linux;

```bash
  $ curl -fsSL https://ollama.ai/install.sh | sh
  $ ollama pull llama3.1:8b
  $ pip install -r requirements.txt
  $ playwright install chromium
  $ python bedihi.py

```

For Windows;

Download & Install Ollama: https://ollama.com/download

After installation: 
```bash
  $ ollama.exe pull llama3.1:8b
  $ pip install -r requirements.txt
  $ playwright install chromium
  $ python bedihi.py
```

(The local LLM will be installed on the system, this may take a few minutes)

## What's next?
- Asynchronous multithreaded brute-force (future)
- AI based backup file detect
- AI-based automatic CAPTCHA bypass

**Join, tweak, and send a PR — this script gets stronger and evolves faster with your contributions.**


## About Me?
- **Linkedin:** https://www.linkedin.com/in/tolgasezer-com-tr

## Donate

- **Bitcoin:** 14xsT25kcSZtRpxmE1GZnLJsPfCeG4cy1t
- https://buymeacoffee.com/tolgasezer
