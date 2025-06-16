import requests
import argparse
import json
import csv
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import concurrent.futures
import sys
import time

@dataclass
class SecurityCheck:
    
    header: str
    present: bool
    value: Optional[str]
    severity: str
    description: str
    remediation: str
    references: List[str]

@dataclass
class ScanResult:

    url: str
    status_code: int
    scan_time: str
    checks: List[SecurityCheck]
    overall_score: int
    risk_level: str

class WebSecurityScanner:

    
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "WebSecurityScanner/1.0"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        
       
        self.security_headers = {
            'strict-transport-security': {
                'severity': 'high',
                'description': 'Enforces secure HTTPS connections',
                'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security']
            },
            'content-security-policy': {
                'severity': 'critical',
                'description': 'Prevents XSS and code injection attacks',
                'remediation': 'Add: Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\';',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
            },
            'x-frame-options': {
                'severity': 'medium',
                'description': 'Prevents clickjacking attacks',
                'remediation': 'Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options']
            },
            'x-content-type-options': {
                'severity': 'medium',
                'description': 'Prevents MIME type sniffing',
                'remediation': 'Add: X-Content-Type-Options: nosniff',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options']
            },
            'referrer-policy': {
                'severity': 'low',
                'description': 'Controls referrer information sent with requests',
                'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy']
            },
            'permissions-policy': {
                'severity': 'medium',
                'description': 'Controls browser features and APIs',
                'remediation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy']
            },
            'x-xss-protection': {
                'severity': 'low',
                'description': 'Legacy XSS protection (deprecated but still useful)',
                'remediation': 'Add: X-XSS-Protection: 1; mode=block',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection']
            },
            'cross-origin-opener-policy': {
                'severity': 'medium',
                'description': 'Isolates browsing context from cross-origin documents',
                'remediation': 'Add: Cross-Origin-Opener-Policy: same-origin',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy']
            },
            'cross-origin-embedder-policy': {
                'severity': 'medium',
                'description': 'Prevents documents from loading cross-origin resources',
                'remediation': 'Add: Cross-Origin-Embedder-Policy: require-corp',
                'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy']
            }
        }

    def scan_url(self, url: str) -> ScanResult:
                try:
           
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            print(f"Scanning: {url}")
            
            
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
           
            checks = []
            for header, config in self.security_headers.items():
                present = header in headers
                value = headers.get(header) if present else None
                
                check = SecurityCheck(
                    header=header,
                    present=present,
                    value=value,
                    severity=config['severity'],
                    description=config['description'],
                    remediation=config['remediation'],
                    references=config['references']
                )
                checks.append(check)
            
            
            score, risk_level = self._calculate_score(checks)
            
            return ScanResult(
                url=url,
                status_code=response.status_code,
                scan_time=datetime.now().isoformat(),
                checks=checks,
                overall_score=score,
                risk_level=risk_level
            )
            
        except requests.exceptions.RequestException as e:
            print(f"Error scanning {url}: {e}")
            return ScanResult(
                url=url,
                status_code=0,
                scan_time=datetime.now().isoformat(),
                checks=[],
                overall_score=0,
                risk_level="error"
            )

    def _calculate_score(self, checks: List[SecurityCheck]) -> Tuple[int, str]:
        
        severity_weights = {
            'critical': 25,
            'high': 20,
            'medium': 15,
            'low': 10
        }
        
        total_possible = sum(severity_weights[check.severity] for check in checks)
        total_achieved = sum(severity_weights[check.severity] for check in checks if check.present)
        
        score = int((total_achieved / total_possible) * 100) if total_possible > 0 else 0
        
        if score >= 90:
            risk_level = "low"
        elif score >= 70:
            risk_level = "medium"
        elif score >= 50:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return score, risk_level

    def scan_multiple_urls(self, urls: List[str], max_workers: int = 5) -> List[ScanResult]:
                results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                results.append(result)
        
        return sorted(results, key=lambda x: x.overall_score)

    def generate_report(self, results: List[ScanResult], format_type: str = "console") -> str:
        """Generate report in specified format"""
        if format_type == "console":
            return self._generate_console_report(results)
        elif format_type == "json":
            return self._generate_json_report(results)
        elif format_type == "csv":
            return self._generate_csv_report(results)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _generate_console_report(self, results: List[ScanResult]) -> str:
        """Generate console-friendly report"""
        report = []
        report.append("=" * 80)
        report.append("WEB SECURITY SCANNER REPORT")
        report.append("=" * 80)
        report.append(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total URLs scanned: {len(results)}")
        report.append("")
        
        for result in results:
            if result.status_code == 0:
                report.append(f"❌ {result.url} - SCAN FAILED")
                report.append("")
                continue
                
            risk_emoji = {
                "low": "✅",
                "medium": "⚠️",
                "high": "🔶",
                "critical": "🔴"
            }
            
            report.append(f"{risk_emoji.get(result.risk_level, '❓')} {result.url}")
            report.append(f"   Score: {result.overall_score}/100 ({result.risk_level.upper()} risk)")
            report.append(f"   Status: {result.status_code}")
            report.append("")
            
            
            missing_headers = [check for check in result.checks if not check.present]
            present_headers = [check for check in result.checks if check.present]
            
            if missing_headers:
                report.append("   Missing Security Headers:")
                for check in sorted(missing_headers, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.severity]):
                    severity_emoji = {'critical': '🔴', 'high': '🔶', 'medium': '🟡', 'low': '🔵'}
                    report.append(f"   {severity_emoji[check.severity]} {check.header.upper()} ({check.severity})")
                    report.append(f"      Description: {check.description}")
                    report.append(f"      Fix: {check.remediation}")
                    report.append("")
            
            if present_headers:
                report.append("   Present Security Headers:")
                for check in present_headers:
                    report.append(f"   ✅ {check.header.upper()}: {check.value}")
                report.append("")
            
            report.append("-" * 80)
            report.append("")
        
        return "\n".join(report)

    def _generate_json_report(self, results: List[ScanResult]) -> str:
                return json.dumps([asdict(result) for result in results], indent=2, default=str)

    def _generate_csv_report(self, results: List[ScanResult]) -> str:
        
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        
        writer.writerow(['URL', 'Status Code', 'Overall Score', 'Risk Level', 'Header', 'Present', 'Value', 'Severity'])
        
        
        for result in results:
            for check in result.checks:
                writer.writerow([
                    result.url,
                    result.status_code,
                    result.overall_score,
                    result.risk_level,
                    check.header,
                    check.present,
                    check.value or '',
                    check.severity
                ])
        
        return output.getvalue()

def main():
    parser = argparse.ArgumentParser(description="Web Security Scanner - Scan websites for missing security headers")
    parser.add_argument('urls', nargs='+', help='URLs to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--format', choices=['console', 'json', 'csv'], default='console', help='Output format (default: console)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--workers', type=int, default=5, help='Max concurrent workers (default: 5)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    args = parser.parse_args()
    
  
    scanner = WebSecurityScanner(timeout=args.timeout, user_agent=args.user_agent)
    
   
    print(f"Starting scan of {len(args.urls)} URL(s)...")
    start_time = time.time()
    
    if len(args.urls) == 1:
        results = [scanner.scan_url(args.urls[0])]
    else:
        results = scanner.scan_multiple_urls(args.urls, max_workers=args.workers)
    
    end_time = time.time()
    print(f"Scan completed in {end_time - start_time:.2f} seconds")
    
    # Generate report
    report = scanner.generate_report(results, format_type=args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()