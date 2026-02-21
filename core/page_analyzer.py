"""Page content fetcher and pre-processor for HackAgent.

Fetches URLs, extracts security-relevant data (headers, scripts, forms,
cookies), and prepares content for AI analysis.
"""
import re
import json
import logging
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger("page_analyzer")


def fetch_page(url, timeout=15):
    """Fetch a URL and return structured security-relevant data."""
    if requests is None:
        raise RuntimeError("requests library not installed: pip install requests")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "cookies": [],
        "html": "",
        "scripts": [],
        "forms": [],
        "links": [],
        "meta_tags": [],
        "comments": [],
        "technologies": [],
        "security_headers": {},
        "errors": [],
    }

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            verify=True,
            allow_redirects=True,
        )
        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["html"] = resp.text[:100000]  # Cap at 100K chars

        # Extract cookies
        for cookie in resp.cookies:
            result["cookies"].append({
                "name": cookie.name,
                "value": cookie.value[:50] + "..." if len(cookie.value) > 50 else cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower(),
            })

        # Analyze security headers
        result["security_headers"] = _check_security_headers(resp.headers)

        # Extract scripts
        result["scripts"] = _extract_scripts(resp.text, url)

        # Extract forms
        result["forms"] = _extract_forms(resp.text, url)

        # Extract links
        result["links"] = _extract_links(resp.text, url)

        # Extract HTML comments
        result["comments"] = _extract_comments(resp.text)

        # Extract meta tags
        result["meta_tags"] = _extract_meta_tags(resp.text)

        # Detect technologies
        result["technologies"] = _detect_technologies(resp.headers, resp.text)

    except requests.exceptions.SSLError as e:
        result["errors"].append(f"SSL Error: {str(e)}")
    except requests.exceptions.ConnectionError as e:
        result["errors"].append(f"Connection Error: {str(e)}")
    except requests.exceptions.Timeout:
        result["errors"].append(f"Timeout after {timeout}s")
    except Exception as e:
        result["errors"].append(f"Error: {str(e)}")

    return result


def _check_security_headers(headers):
    """Check for presence and quality of security headers."""
    checks = {}
    header_map = {k.lower(): v for k, v in headers.items()}

    security_headers = {
        "Strict-Transport-Security": "hsts",
        "Content-Security-Policy": "csp",
        "X-Frame-Options": "x_frame_options",
        "X-Content-Type-Options": "x_content_type",
        "X-XSS-Protection": "x_xss_protection",
        "Referrer-Policy": "referrer_policy",
        "Permissions-Policy": "permissions_policy",
        "Cross-Origin-Opener-Policy": "coop",
        "Cross-Origin-Resource-Policy": "corp",
        "Cross-Origin-Embedder-Policy": "coep",
    }

    for header, key in security_headers.items():
        value = header_map.get(header.lower())
        checks[key] = {
            "present": value is not None,
            "value": value,
            "severity": "Medium" if value is None else "Info",
        }

    # Flag especially risky missing headers
    if not checks["hsts"]["present"]:
        checks["hsts"]["severity"] = "High"
    if not checks["csp"]["present"]:
        checks["csp"]["severity"] = "High"

    return checks


def _extract_scripts(html, base_url):
    """Extract script sources and inline scripts."""
    scripts = []

    # External scripts
    src_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    for match in src_pattern.finditer(html):
        src = match.group(1)
        full_url = urljoin(base_url, src)
        scripts.append({"type": "external", "src": full_url})

    # Inline scripts (just first 500 chars each)
    inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)
    for match in inline_pattern.finditer(html):
        content = match.group(1).strip()
        if content:
            scripts.append({
                "type": "inline",
                "preview": content[:500],
                "length": len(content),
            })

    return scripts[:30]  # Cap at 30 scripts


def _extract_forms(html, base_url):
    """Extract form details for input vector analysis."""
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.I)
    method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.I)
    input_pattern = re.compile(
        r'<(?:input|textarea|select)[^>]*(?:name=["\']([^"\']*)["\'])?[^>]*'
        r'(?:type=["\']([^"\']*)["\'])?',
        re.I,
    )

    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        form_body = form_match.group(1)

        action_match = action_pattern.search(form_html)
        method_match = method_pattern.search(form_html)

        action = urljoin(base_url, action_match.group(1)) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "GET"

        inputs = []
        for inp_match in input_pattern.finditer(form_body):
            name = inp_match.group(1) or "unnamed"
            input_type = inp_match.group(2) or "text"
            inputs.append({"name": name, "type": input_type})

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms[:10]


def _extract_links(html, base_url):
    """Extract all links from the page."""
    links = []
    pattern = re.compile(r'<a[^>]+href=["\']([^"\'#]+)["\']', re.I)
    seen = set()
    for match in pattern.finditer(html):
        href = match.group(1)
        full_url = urljoin(base_url, href)
        if full_url not in seen:
            seen.add(full_url)
            links.append(full_url)
    return links[:50]


def _extract_comments(html):
    """Extract HTML comments that might contain sensitive info."""
    comments = []
    pattern = re.compile(r'<!--(.*?)-->', re.S)
    for match in pattern.finditer(html):
        comment = match.group(1).strip()
        if comment and len(comment) > 5:
            comments.append(comment[:500])
    return comments[:20]


def _extract_meta_tags(html):
    """Extract meta tags for information gathering."""
    meta_tags = []
    pattern = re.compile(r'<meta[^>]+>', re.I)
    name_pattern = re.compile(r'(?:name|property)=["\']([^"\']+)["\']', re.I)
    content_pattern = re.compile(r'content=["\']([^"\']+)["\']', re.I)

    for match in pattern.finditer(html):
        tag = match.group(0)
        name_match = name_pattern.search(tag)
        content_match = content_pattern.search(tag)
        if name_match and content_match:
            meta_tags.append({
                "name": name_match.group(1),
                "content": content_match.group(1)[:200],
            })

    return meta_tags[:20]


def _detect_technologies(headers, html):
    """Detect web technologies from headers and HTML content."""
    techs = []
    header_map = {k.lower(): v for k, v in headers.items()}

    # Server header
    server = header_map.get("server")
    if server:
        techs.append({"name": "Server", "value": server, "source": "header"})

    # X-Powered-By
    powered_by = header_map.get("x-powered-by")
    if powered_by:
        techs.append({"name": "X-Powered-By", "value": powered_by, "source": "header"})

    # Technology fingerprints in HTML
    tech_patterns = {
        "WordPress": [r'wp-content/', r'wp-includes/', r'wordpress'],
        "Drupal": [r'Drupal', r'drupal\.js', r'/sites/default/'],
        "Joomla": [r'/media/jui/', r'Joomla'],
        "React": [r'react\.', r'__NEXT_DATA__', r'_next/'],
        "Angular": [r'ng-app', r'angular\.', r'ng-version'],
        "Vue.js": [r'vue\.', r'v-bind', r'v-if', r'__vue__'],
        "jQuery": [r'jquery[\.\-]', r'jQuery'],
        "Bootstrap": [r'bootstrap[\.\-]'],
        "Nginx": [r'nginx', r'openresty'],
        "Apache": [r'apache', r'httpd'],
        "PHP": [r'\.php', r'PHPSESSID'],
        "ASP.NET": [r'__VIEWSTATE', r'\.aspx', r'asp\.net'],
        "Django": [r'csrfmiddlewaretoken', r'django'],
        "Rails": [r'rails', r'_rails_'],
        "Laravel": [r'laravel', r'XSRF-TOKEN'],
        "Spring": [r'spring', r'jsessionid'],
        "Node.js/Express": [r'express', r'connect\.sid'],
        "Cloudflare": [r'cloudflare', r'cf-ray'],
        "AWS": [r'amazonaws', r'x-amz-'],
        "Jenkins": [r'jenkins', r'/jenkins/'],
        "GitLab": [r'gitlab'],
        "Jira": [r'jira', r'atlassian'],
        "Confluence": [r'confluence'],
    }

    html_lower = html.lower() if html else ""
    headers_str = str(headers).lower()

    for tech, patterns in tech_patterns.items():
        for pattern in patterns:
            if re.search(pattern, html_lower) or re.search(pattern, headers_str):
                techs.append({"name": tech, "source": "fingerprint"})
                break

    return techs


def quick_vuln_check(page_data):
    """Run quick automated vulnerability checks on fetched page data."""
    findings = []

    # Check security headers
    for header_key, info in page_data.get("security_headers", {}).items():
        if not info.get("present"):
            findings.append({
                "type": "missing_header",
                "severity": info.get("severity", "Medium"),
                "title": f"Missing {header_key.upper().replace('_', '-')} header",
                "description": f"The security header is not set.",
            })

    # Check cookies
    for cookie in page_data.get("cookies", []):
        if not cookie.get("secure"):
            findings.append({
                "type": "insecure_cookie",
                "severity": "Medium",
                "title": f"Cookie '{cookie['name']}' missing Secure flag",
                "description": "Cookie transmitted over unencrypted connections.",
            })
        if not cookie.get("httponly"):
            findings.append({
                "type": "insecure_cookie",
                "severity": "Medium",
                "title": f"Cookie '{cookie['name']}' missing HttpOnly flag",
                "description": "Cookie accessible to JavaScript (XSS risk).",
            })

    # Check for dangerous JS patterns
    for script in page_data.get("scripts", []):
        preview = script.get("preview", "")
        dangerous = ["eval(", "document.write(", "innerHTML", ".innerHTML=",
                      "window.location=", "document.cookie"]
        for pattern in dangerous:
            if pattern in preview:
                findings.append({
                    "type": "dangerous_js",
                    "severity": "Medium",
                    "title": f"Potentially dangerous JS: {pattern}",
                    "description": f"Found '{pattern}' in inline script.",
                })

    # Check for information disclosure in comments
    sensitive_patterns = ["password", "secret", "api_key", "apikey", "token",
                          "todo", "fixme", "hack", "bug", "admin", "debug"]
    for comment in page_data.get("comments", []):
        for pattern in sensitive_patterns:
            if pattern in comment.lower():
                findings.append({
                    "type": "info_disclosure",
                    "severity": "Low",
                    "title": f"Sensitive keyword in HTML comment: '{pattern}'",
                    "description": f"Comment contains potentially sensitive information.",
                })
                break

    return findings
