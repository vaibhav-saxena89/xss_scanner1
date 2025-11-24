# Python Reflected XSS Scanner

This project is a Python-based reflected XSS scanner built as part of a security engineering assignment.

## Features
- Supports GET and POST
- PayloadGenerator that adapts payloads based on context (text-node, attribute-value, JS, attribute-name)
- Reflection detection in HTTP responses
- HTML report output

## Usage
python xss_scanner.py --url "https://example.com" --params "q,search"

## Requirements
pip install -r requirements.txt
