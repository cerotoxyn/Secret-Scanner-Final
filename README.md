# Secret Scanner CLI Final
Recording of my scanner working: https://drive.google.com/file/d/1X3s5omffvNhelCp2WMqM5xZnDszcn4Iu/view?usp=drive_link
## Overview
This project is a Python based command line tool that scans a file or directory for possible hardcoded secrets. It uses regular expressions to detect token and key formats commonly associated with exposed credentials.

## Features
- Accepts a file or directory as input
- Recursively scans directories
- Uses regex to detect common secret patterns
- Reports:
  - filename
  - line number
  - matched string (masked)
- Includes logging
- Uses argparse for a clear CLI interface

## Detection Logic
The scanner looks for known secret formats using regular expressions. The current implementation includes these example patterns:

1. GitHub Personal Access Token (classic)  
   Example regex: `\bghp_[A-Za-z0-9]{36}\b`

2. GitHub Fine-Grained Personal Access Token  
   Example regex: `\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b`

3. Google API Key  
   Example regex: `\bAIza[0-9A-Za-z\-_]{35}\b`

4. Slack Bot Token  
   Example regex: `\bxoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}\b`

5. Stripe Standard API Key  
   Example regex: `\bsk_live_[0-9A-Za-z]{24}\b`

6. AWS Access Key ID  
   Example regex: `\bAKIA[0-9A-Z]{16}\b`

7. OpenAI API Key  
   Example regex: `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`

8. Private Key Block  
   Example regex: `-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`


### Scan a single file
```bash
python secret_scanner.py example.py
