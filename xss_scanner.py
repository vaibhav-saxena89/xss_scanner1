import argparse
import requests
import threading
import concurrent.futures
import time
import random
import string
import html
import json
import os
import re
from urllib.parse import urlparse, parse_qsl, urlencode

class PayloadGenerator:
    

    def __init__(self, randomize=True, marker_base="P"):
        self.randomize = randomize
        self.marker_base = marker_base

    def _rand(self, n=6):
        if not self.randomize:
            return "RND"
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

    def marker(self, label):
        """Return a unique marker token used in payloads for reflection detection"""
        return f"{self.marker_base}_{label}_{self._rand(5)}"

    def payloads_for(self, context):
        
        ctx = context.lower()
        if ctx == "attribute-name":
            
            m = self.marker("attrname")
            
            return [m, m + 'x', 'on' + m, m + '-data']
        elif ctx == "attribute-value":
            m = html.escape(self.marker("attrval"))
           
            return [
                f'"{m}"',          
                f"'{m}'",          
                f'{m}" onmouseover=alert(1)', 
                m
            ]
        elif ctx == "text-node":
            m = self.marker("text")
            
            return [
                m,
                f"<{m}>",
                f"&lt;{m}&gt;"
            ]
        elif ctx == "js":
            m = self.marker("js")
            
            return [
                f'"{m}"',
                f"';console.log('{m}');//",
                f"');alert('{m}');//"
            ]
        else:
            
            m = self.marker("generic")
            return [m]

class ReflectedXSSScanner:
    def __init__(self, target_url, params, method="GET", data=None, headers=None, cookies=None,
                 contexts=None, timeout=10, concurrency=5, randomize=True):
        self.target_url = target_url
        self.params = params[:] 
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.contexts = contexts or ["attribute-name", "attribute-value", "text-node", "js"]
        self.timeout = timeout
        self.executor_workers = concurrency
        self.payload_gen = PayloadGenerator(randomize=randomize)
        self.results = []  
        
        self.session = requests.Session()
        if self.headers:
            self.session.headers.update(self.headers)
        if self.cookies:
            
            self.session.cookies.update(self.cookies)

    def _inject_param_value(self, base_params, param_to_inject, injection_value):
        
        params = dict(base_params)  
        params[param_to_inject] = injection_value
        return params

    def _send_request(self, params):
        try:
            if self.method == "GET":
                resp = self.session.get(self.target_url, params=params, timeout=self.timeout, allow_redirects=True)
            else:
                
                if isinstance(self.data, dict) and self.data.get("_json_body"):
                    
                    json_body = dict(self.data["_json_body"])
                    
                    for k, v in params.items():
                        if k in json_body:
                            json_body[k] = v
                    resp = self.session.post(self.target_url, json=json_body, timeout=self.timeout, allow_redirects=True)
                else:
                    resp = self.session.post(self.target_url, data=params, timeout=self.timeout, allow_redirects=True)
            return resp
        except Exception as e:
            return e

    def _detect_reflection(self, response_text, injected_token):
        
        if not isinstance(response_text, str):
            return False, []
        found = injected_token in response_text
        if not found:
            return False, []
        guesses = []

        
        for m in re.finditer(re.escape(injected_token), response_text):
            i = m.start()
            
            window_left = response_text[max(0, i-60):i+len(injected_token)+60]

            
            script_before = response_text.rfind("<script", 0, i)
            script_close = response_text.find("</script>", i)
            if script_before != -1 and script_close != -1 and script_before < i < script_close:
                guesses.append("js")
                continue

            
            lt = response_text.rfind("<", 0, i)
            gt = response_text.find(">", i)
            if lt != -1 and gt != -1 and lt < i < gt:
                
                after = response_text[i:i+20]
                before = response_text[max(lt, i-40):i]
                if re.search(r"\b" + re.escape(injected_token) + r"\s*=", response_text[max(lt, i-40):i+20]):
                    guesses.append("attribute-name")
                
                quote_match = re.search(r'["\']([^"\']*' + re.escape(injected_token) + r'[^"\']*)["\']', window_left)
                if quote_match:
                    if "attribute-value" not in guesses:
                        guesses.append("attribute-value")
                
                if not guesses:
                    guesses.append("attribute")
            else:
                
                guesses.append("text-node")

        
        guesses = list(dict.fromkeys(guesses))
        return True, guesses

    def _scan_param_context(self, param, context):
        
        findings = []
        payloads = self.payload_gen.payloads_for(context)
        for payload in payloads:
            
            base_params = {}
            
            injection_token = payload

            
            if context == "attribute-name":
                
                params_for_request = {injection_token: "1"}
            else:
                
                params_for_request = {p: "" for p in self.params}
                params_for_request.update(self.data if isinstance(self.data, dict) else {})
                params_for_request[param] = injection_token

            resp = self._send_request(params_for_request)
            if isinstance(resp, Exception):
                findings.append({
                    "param": param,
                    "context": context,
                    "payload": payload,
                    "error": str(resp),
                    "status": None,
                    "url": self.target_url
                })
                continue

            body = resp.text or ""
            found, guessed = self._detect_reflection(body, injection_token)
            if found:
                findings.append({
                    "param": param,
                    "context": context,
                    "payload": payload,
                    "status": resp.status_code,
                    "guessed_contexts": guessed,
                    "snippet": self._make_snippet(body, injection_token),
                    "url": resp.url
                })
        return findings

    def _make_snippet(self, body, token, radius=60):
        idx = body.find(token)
        if idx == -1:
            return ""
        start = max(0, idx - radius)
        end = min(len(body), idx + len(token) + radius)
        snippet = body[start:end]
        
        return snippet.replace("\n", " ").replace("\r", " ")

    def run(self):
        """
        Run the scan using concurrency across param x contexts.
        """
        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.executor_workers) as executor:
            futures = []
            for param in self.params:
                for ctx in self.contexts:
                    futures.append(executor.submit(self._scan_param_context, param, ctx))
            for fut in concurrent.futures.as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        self.results.extend(res)
                except Exception as e:
                    print("Scan task error:", e)

    def generate_html_report(self, out_path="report.html"):
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        html_parts = [
            "<!doctype html>",
            "<html><head><meta charset='utf-8'><title>XSS Scan Report</title>",
            "<style>body{font-family:Arial;padding:16px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px} th{background:#f2f2f2}</style>",
            "</head><body>",
            f"<h1>Reflected XSS Scan Report</h1>",
            f"<p>Target: {html.escape(self.target_url)}</p>",
            f"<p>Generated: {now}</p>",
            "<table><thead><tr><th>Param</th><th>Context</th><th>Payload</th><th>Guessed Contexts</th><th>HTTP Status</th><th>Snippet</th></tr></thead><tbody>"
        ]
        if not self.results:
            html_parts.append("<tr><td colspan='6'>No reflections found.</td></tr>")
        else:
            for r in self.results:
                param = html.escape(str(r.get("param", "")))
                ctx = html.escape(str(r.get("context", "")))
                payload = html.escape(str(r.get("payload", "")))
                guessed = html.escape(", ".join(r.get("guessed_contexts", []))) if r.get("guessed_contexts") else ""
                status = html.escape(str(r.get("status", "")))
                snippet = html.escape(r.get("snippet", "") or "")
                html_parts.append(f"<tr><td>{param}</td><td>{ctx}</td><td><code>{payload}</code></td><td>{guessed}</td><td>{status}</td><td><pre style='white-space:pre-wrap'>{snippet}</pre></td></tr>")
        html_parts.append("</tbody></table>")
        html_parts.append("<h3>Notes</h3><ul><li>Detection: substring matching of unique markers. Heuristic guesses show likely context.</li></ul>")
        html_parts.append("</body></html>")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))
        return out_path


def parse_headers_cookie(s):
    
    if not s:
        return {}
    items = re.split(r"[;|,]\s*", s)
    out = {}
    for it in items:
        if not it.strip():
            continue
        if ":" in it:
            k, v = it.split(":", 1)
            out[k.strip()] = v.strip()
    return out

def main():
    parser = argparse.ArgumentParser(description="Reflected XSS Scanner (simple)")
    parser.add_argument("--url", required=True, help="Target URL (include scheme http/https)")
    parser.add_argument("--params", required=True, help="Comma-separated parameter names to test (e.g., q,search,page)")
    parser.add_argument("--method", choices=["GET","POST"], default="GET")
    parser.add_argument("--data", help="For POST: JSON string or key1=val1;key2=val2 template (if using JSON, prefix with json:)")
    parser.add_argument("--headers", help="Custom headers e.g. 'User-Agent: myagent;X-Auth: token'")
    parser.add_argument("--cookies", help="Cookies e.g. 'sessionid=abc;csrftoken=def'")
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--no-random", action="store_true", help="Disable payload randomization")
    parser.add_argument("--out", default="report.html", help="Output HTML report filename")
    args = parser.parse_args()

    params = [p.strip() for p in args.params.split(",") if p.strip()]
    headers = parse_headers_cookie(args.headers)
    cookies = parse_headers_cookie(args.cookies)
    data = None
    if args.data:
        s = args.data.strip()
        if s.startswith("json:"):
            try:
                j = json.loads(s[len("json:"):])
                data = {"_json_body": j}
            except Exception as e:
                print("Invalid JSON for --data:", e)
                return
        else:
            
            d = {}
            for kv in re.split(r"[;|,]\s*", s):
                if not kv:
                    continue
                if "=" in kv:
                    k,v = kv.split("=",1)
                    d[k.strip()] = v
            data = d

    scanner = ReflectedXSSScanner(
        target_url=args.url,
        params=params,
        method=args.method,
        data=data,
        headers=headers,
        cookies=cookies,
        concurrency=args.concurrency,
        randomize=(not args.no_random)
    )
    print(f"[+] Running scanner on {args.url} | method={args.method} | params={params}")
    scanner.run()
    out = scanner.generate_html_report(args.out)
    print(f"[+] Report written to {out}")
    if scanner.results:
        print("[+] Findings:")
        for r in scanner.results:
            print(f" - param={r.get('param')} context={r.get('context')} payload={r.get('payload')} guessed={r.get('guessed_contexts')}")
    else:
        print("[-] No reflections found.")

if __name__ == "__main__":
    main()
