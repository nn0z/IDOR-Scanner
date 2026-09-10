# IDOR SCANNER v2.0
import sys
import time
import re
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import requests

TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

COLORS = {
    "GET": "\033[92m",
    "POST": "\033[94m",
    "PUT": "\033[93m",
    "DELETE": "\033[91m",
    "OTHER": "\033[95m",
    "CYAN": "\033[96m",
    "GRAY": "\033[90m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}


class IDORScanner:
    def __init__(self):
        self.discovered_urls = set()
        self.idor_vulnerable = []
        self.real_idors = []
        self.all_forms = []
        self.all_get_params = []
        self.all_path_ids = []
        self.base_url = ""
        self.total_tests = 0
        self.vulnerable_tests = 0
        self.visited_urls = set()
        self.max_pages = 30
        self.api_endpoints = set()
        self.false_positives = 0
        self.potential_idors = []
        self.scan_start_time = time.time()
        self.sent_summary = False

        self.sensitive_keywords = {
            'email', 'e-mail', 'mail', '@', 'phone', 'mobile', 'cell', 'telephone',
            'address', 'street', 'city', 'state', 'zip', 'postal', 'country',
            'name', 'fullname', 'firstname', 'lastname', 'username', 'user',
            'profile', 'avatar', 'picture', 'photo', 'image',
            'birth', 'birthday', 'age', 'gender', 'sex',
            'nationality', 'national_id', 'ssn', 'social', 'security',
            'card', 'credit', 'debit', 'bank', 'account', 'balance',
            'transaction', 'payment', 'invoice', 'bill', 'receipt',
            'price', 'cost', 'total', 'amount', 'currency',
            'order', 'purchase', 'cart', 'checkout', 'shipping',
            'billing', 'subscription', 'membership', 'plan',
            'medical', 'health', 'patient', 'doctor', 'hospital', 'clinic',
            'diagnosis', 'treatment', 'prescription', 'medication', 'drug',
            'allergy', 'blood', 'weight', 'height', 'pressure', 'sugar',
            'insurance', 'policy', 'claim', 'benefit',
            'employee', 'staff', 'worker', 'manager', 'department',
            'salary', 'payroll', 'bonus', 'commission', 'overtime',
            'position', 'title', 'role', 'permission', 'access',
            'hire', 'fire', 'terminate', 'resign',
            'student', 'teacher', 'professor', 'course', 'class', 'grade',
            'score', 'gpa', 'transcript', 'diploma', 'degree', 'certificate',
            'exam', 'quiz', 'assignment', 'homework',
            'passport', 'visa', 'citizen', 'resident', 'immigration',
            'tax', 'id', 'license', 'driver', 'vehicle', 'car', 'plate',
            'crime', 'criminal', 'court', 'judge', 'lawyer', 'attorney',
            'police', 'arrest', 'warrant', 'prison', 'jail',
            'token', 'api_key', 'secret', 'password', 'pass', 'pwd',
            'auth', 'authentication', 'authorization', 'session', 'cookie',
            'ip', 'mac', 'device', 'browser', 'user_agent',
            'database', 'db', 'table', 'column', 'row', 'record',
            'company', 'business', 'client', 'customer', 'partner',
            'vendor', 'supplier', 'distributor', 'reseller',
            'contract', 'agreement', 'nda', 'proposal', 'quote',
            'project', 'task', 'deadline', 'milestone', 'deliverable',
            'friend', 'follower', 'following', 'connection', 'network',
            'message', 'chat', 'comment', 'post', 'tweet',
            'like', 'share', 'react', 'mention', 'tag',
            'group', 'community', 'forum', 'thread',
            'confidential', 'private', 'internal', 'restricted',
            'personal', 'sensitive', 'classified', 'top_secret',
            'passcode', 'pin', 'otp', '2fa', 'verification',
            'reset', 'recovery', 'backup', 'archive', 'log',
            'audit', 'trace', 'track', 'monitor', 'surveillance'
        }

        self.sensitive_patterns = [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            r'\+\d{1,3}[-.]?\d{3,4}[-.]?\d{3,4}[-.]?\d{3,4}',
            r'\d{3}[-.]?\d{3}[-.]?\d{4}',
            r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            r'\d{1,2}/\d{1,2}/\d{2,4}',
            r'\d{4}-\d{1,2}-\d{1,2}',
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b\d{10,15}\b',
            r'[a-zA-Z0-9]{32,40}',
        ]

    def send_telegram_message(self, message):
        if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE" or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID_HERE":
            return

        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, data=payload, timeout=10)
            return response.status_code == 200
        except:
            return False

    def send_instant_idor(self, vuln_data):
        if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE" or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID_HERE":
            return

        message = f"""
🔴 <b>🚨 IDOR DETECTED INSTANTLY!</b>

📍 <b>Target:</b> <code>{self.base_url}</code>
📌 <b>Endpoint:</b> <code>{vuln_data.get('test_url', 'N/A')}</code>
🔑 <b>Parameter:</b> <code>{vuln_data.get('parameter', 'N/A')}</code>
🔄 <b>Swapped:</b> {vuln_data.get('original_id', 'N/A')} → {vuln_data.get('test_id', 'N/A')}
📊 <b>Status:</b> {vuln_data.get('status', 'N/A')}
🏷️ <b>Type:</b> {vuln_data.get('type', 'N/A')}

<i>⚠️ This vulnerability was found during live scanning!</i>
        """
        self.send_telegram_message(message)

    def send_final_summary(self):
        if self.sent_summary:
            return
        self.sent_summary = True

        scan_duration = time.time() - self.scan_start_time
        minutes = int(scan_duration // 60)
        seconds = int(scan_duration % 60)

        total_endpoints = len(self.all_get_params) + len(self.all_path_ids)
        if total_endpoints > 0:
            security_score = max(0, 100 - (len(self.real_idors) / total_endpoints * 100))
        else:
            security_score = 100

        security_score = round(security_score, 1)

        if security_score >= 90:
            security_level = "🟢 <b>Excellent</b> - Very Secure"
        elif security_score >= 70:
            security_level = "🟡 <b>Good</b> - Minor Issues"
        elif security_score >= 50:
            security_level = "🟠 <b>Moderate</b> - Needs Review"
        else:
            security_level = "🔴 <b>Critical</b> - High Risk"

        idor_list = ""
        if self.real_idors:
            idor_list = "\n\n<b>📋 Detected IDORs:</b>\n"
            for idx, vuln in enumerate(self.real_idors, 1):
                idor_list += f"\n{idx}. <b>Type:</b> {vuln.get('type', 'N/A')}\n"
                idor_list += f"   <b>URL:</b> <code>{vuln.get('test_url', 'N/A')[:80]}</code>\n"
                idor_list += f"   <b>Parameter:</b> {vuln.get('parameter', 'N/A')}\n"
                idor_list += f"   <b>Swapped:</b> {vuln.get('original_id', 'N/A')} → {vuln.get('test_id', 'N/A')}\n"

        message = f"""
               📊 IDOR SCAN COMPLETE REPORT                    

🌐 <b>Target URL:</b> <code>{self.base_url}</code>
⏱️ <b>Scan Duration:</b> {minutes}m {seconds}s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📈 <b>SCAN STATISTICS:</b>
├ 📄 Pages Discovered: {len(self.discovered_urls)}
├ 🔗 Query ID Endpoints: {len(self.all_get_params)}
├ 🛤️ Path ID Endpoints: {len(self.all_path_ids)}
├ 🔌 API Endpoints: {len(self.api_endpoints)}
├ 🧪 Total Tests Performed: {self.total_tests}
├ ✅ Real IDORs Found: <b>{len(self.real_idors)}</b>
├ ⚠️ Potential IDORs: {len(self.potential_idors)}
└ ❌ False Positives Filtered: {self.false_positives}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️ <b>SECURITY ASSESSMENT:</b>
├ Score: <b>{security_score}%</b>
└ Status: {security_level}
{idor_list}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

<i>🤖 Scan performed by neutron IDOR Scanner</i>

<a href="https://github.com/nn0z/">🔗 <b>Github</b></a>
<a href="https://www.instagram.com/e1z/">🔗 <b>Instagram</b></a>
        """

        self.send_telegram_message(message)

    def print_banner(self):
        banner = f"""
          ██╗ ██████╗   ██████╗  ██████╗ 
          ██║ ██╔══██╗ ██╔═══██╗ ██╔══██╗
          ██║ ██║  ██║ ██║   ██║ ██████╔╝{COLORS['CYAN']} >neutron{COLORS['RESET']}
          ██║ ██║  ██║ ██║   ██║ ██╔══██╗{COLORS['CYAN']}   v2.0{COLORS['RESET']}
          ██║ ██████╔╝ ╚██████╔╝ ██║  ██║
          ╚═╝ ╚═════╝   ╚═════╝  ╚═╝  ╚═╝
        {COLORS['RED']}[ Automated IDOR Discovery Engine ]{COLORS['RESET']}  """
        print(banner)

    def is_sensitive_content(self, response_text):
        if not response_text or len(response_text) < 50:
            return False

        response_lower = response_text.lower()
        keyword_matches = 0
        for keyword in self.sensitive_keywords:
            if keyword.lower() in response_lower:
                keyword_matches += 1
                if keyword_matches >= 2:
                    return True

        for pattern in self.sensitive_patterns:
            if re.search(pattern, response_text):
                return True

        words = response_lower.split()
        if words:
            sensitive_ratio = keyword_matches / len(words)
            if sensitive_ratio > 0.05:
                return True

        return False

    def is_public_content(self, response_text):
        public_patterns = [
            r'help|faq|support|contact|about|privacy|terms|policy',
            r'error|404|not found|page not found',
            r'login|signin|register|signup|create account',
            r'home|main|index|welcome',
            r'search|find|browse|category|department',
            r'product|item|goods|merchandise',
        ]

        response_lower = response_text.lower()
        for pattern in public_patterns:
            if re.search(pattern, response_lower):
                return True
        return False

    def extract_numeric_ids_from_path(self, url):
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        numeric_parts = []

        for i, part in enumerate(path_parts):
            if re.match(r'^\d+$', part):
                numeric_parts.append({
                    'index': i,
                    'value': part,
                    'path': parsed.path
                })

        return numeric_parts

    def extract_numeric_id_params(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        numeric_params = {}
        for key, values in params.items():
            if values and re.match(r'^\d+$', values[0]):
                numeric_params[key] = values[0]
        if numeric_params:
            return {
                'url': url,
                'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                'params': params,
                'numeric_params': numeric_params,
                'type': 'query'
            }
        return None

    def extract_api_endpoints_fast(self, page_content):
        endpoints = set()
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, page_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[-1] if len(match) > 1 else match[0]
                else:
                    endpoint = match

                if endpoint and not endpoint.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    full_url = urljoin(self.base_url, endpoint)
                    if self.is_same_domain(full_url):
                        endpoints.add(full_url)
        return endpoints

    def get_all_links_fast(self, page):
        links = set()

        try:
            script = """
            () => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.getAttribute('href');
                    if (href && !href.startsWith('#') && !href.startsWith('javascript:') && 
                        !href.startsWith('mailto:') && !href.startsWith('tel:')) {
                        links.push(href);
                    }
                });
                document.querySelectorAll('[data-url], [data-href], [data-link], [data-api]').forEach(el => {
                    ['data-url', 'data-href', 'data-link', 'data-api'].forEach(attr => {
                        const value = el.getAttribute(attr);
                        if (value) links.push(value);
                    });
                });
                document.querySelectorAll('[onclick]').forEach(el => {
                    const onclick = el.getAttribute('onclick');
                    if (onclick) {
                        const match = onclick.match(/location\\s*=\\s*['"]([^'"]+)['"]/);
                        if (match) links.push(match[1]);
                    }
                });
                return links;
            }
            """
            hrefs = page.evaluate(script)
            for href in hrefs:
                if href and isinstance(href, str):
                    try:
                        full_url = urljoin(self.base_url, href)
                        if self.is_same_domain(full_url):
                            links.add(full_url)
                    except:
                        pass
        except Exception as e:
            print(f"{COLORS['YELLOW']}⚠ Error in JavaScript extraction: {str(e)[:30]}{COLORS['RESET']}")

        try:
            a_tags = page.locator("a[href]")
            count = a_tags.count()
            for i in range(min(count, 100)):
                try:
                    href = a_tags.nth(i).get_attribute("href")
                    if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                        full_url = urljoin(self.base_url, href)
                        if self.is_same_domain(full_url):
                            links.add(full_url)
                except:
                    pass
        except Exception as e:
            print(f"{COLORS['YELLOW']}⚠ Error in locator extraction: {str(e)[:30]}{COLORS['RESET']}")

        try:
            html_content = page.content()
            href_pattern = r'href=["\']([^"\']+)["\']'
            matches = re.findall(href_pattern, html_content, re.IGNORECASE)
            for href in matches:
                if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    try:
                        full_url = urljoin(self.base_url, href)
                        if self.is_same_domain(full_url):
                            links.add(full_url)
                    except:
                        pass
        except:
            pass

        return links

    def get_all_forms_fast(self, page):
        forms = []
        try:
            script = """
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const action = form.getAttribute('action') || '';
                    const method = (form.getAttribute('method') || 'get').toUpperCase();
                    const inputs = [];
                    form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])').forEach(inp => {
                        inputs.push({
                            name: inp.getAttribute('name') || '',
                            type: inp.getAttribute('type') || 'text'
                        });
                    });
                    forms.push({ action, method, inputs });
                });
                return forms;
            }
            """
            form_data = page.evaluate(script)
            for data in form_data:
                form_url = urljoin(self.base_url, data['action']) if data['action'] else page.url
                forms.append({
                    'url': form_url,
                    'method': data['method'],
                    'action': data['action'],
                    'inputs': data['inputs'],
                })
        except:
            pass

        if not forms:
            try:
                form_elements = page.locator("form")
                for i in range(form_elements.count()):
                    try:
                        form = form_elements.nth(i)
                        action = form.get_attribute("action") or ""
                        method = form.get_attribute("method") or "get"
                        form_url = urljoin(self.base_url, action) if action else page.url

                        inputs = []
                        input_elements = form.locator(
                            "input:not([type='hidden']):not([type='submit']):not([type='button'])")
                        for j in range(min(input_elements.count(), 20)):
                            try:
                                inp = input_elements.nth(j)
                                input_name = inp.get_attribute("name") or ""
                                input_type = inp.get_attribute("type") or "text"
                                inputs.append({
                                    'name': input_name,
                                    'type': input_type,
                                })
                            except:
                                pass

                        forms.append({
                            'url': form_url,
                            'method': method.upper(),
                            'action': action,
                            'inputs': inputs,
                        })
                    except:
                        pass
            except:
                pass

        return forms

    def is_same_domain(self, url):
        try:
            parsed_base = urlparse(self.base_url)
            parsed_url = urlparse(url)
            return parsed_base.netloc == parsed_url.netloc
        except:
            return False

    def discover_pages(self, page):
        print(f"{COLORS['CYAN']}►{COLORS['RESET']} Discovering pages and numeric ID endpoints...")

        links = self.get_all_links_fast(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(links)} unique links{COLORS['RESET']}")

        page_content = page.content()
        api_endpoints = self.extract_api_endpoints_fast(page_content)
        self.api_endpoints.update(api_endpoints)
        print(f"{COLORS['GRAY']}   ↳ Found {len(api_endpoints)} potential API endpoints{COLORS['RESET']}")

        if page.url not in self.discovered_urls:
            self.discovered_urls.add(page.url)

        for link in links:
            if link not in self.discovered_urls:
                self.discovered_urls.add(link)
                id_data = self.extract_numeric_id_params(link)
                if id_data:
                    self.all_get_params.append(id_data)

                path_ids = self.extract_numeric_ids_from_path(link)
                if path_ids:
                    self.all_path_ids.append({
                        'url': link,
                        'path_ids': path_ids,
                        'base_url': link
                    })

        for endpoint in api_endpoints:
            id_data = self.extract_numeric_id_params(endpoint)
            if id_data:
                self.all_get_params.append(id_data)

            path_ids = self.extract_numeric_ids_from_path(endpoint)
            if path_ids:
                self.all_path_ids.append({
                    'url': endpoint,
                    'path_ids': path_ids,
                    'base_url': endpoint
                })

        forms = self.get_all_forms_fast(page)
        print(f"{COLORS['GRAY']}   ↳ Found {len(forms)} forms{COLORS['RESET']}")
        self.all_forms.extend(forms)

        print(f"{COLORS['GRAY']}   ↳ Total discovered URLs: {len(self.discovered_urls)}{COLORS['RESET']}")
        return list(self.discovered_urls)

    def crawl_pages(self, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Crawling discovered pages...")

        pages_to_visit = list(self.discovered_urls)[:self.max_pages]
        total_pages = len(pages_to_visit)

        for idx, url in enumerate(pages_to_visit, 1):
            if url in self.visited_urls:
                continue

            print(f"{COLORS['GRAY']}   [{idx}/{total_pages}] Visiting: {url[:60]}...{COLORS['RESET']}")

            try:
                page = context.new_page()
                page.goto(url, timeout=8000, wait_until="domcontentloaded")
                self.visited_urls.add(url)

                new_links = self.get_all_links_fast(page)
                for link in new_links:
                    if link not in self.discovered_urls:
                        self.discovered_urls.add(link)
                        id_data = self.extract_numeric_id_params(link)
                        if id_data:
                            self.all_get_params.append(id_data)

                        path_ids = self.extract_numeric_ids_from_path(link)
                        if path_ids:
                            self.all_path_ids.append({
                                'url': link,
                                'path_ids': path_ids,
                                'base_url': link
                            })

                page_content = page.content()
                api_endpoints = self.extract_api_endpoints_fast(page_content)
                self.api_endpoints.update(api_endpoints)
                for endpoint in api_endpoints:
                    id_data = self.extract_numeric_id_params(endpoint)
                    if id_data:
                        self.all_get_params.append(id_data)

                    path_ids = self.extract_numeric_ids_from_path(endpoint)
                    if path_ids:
                        self.all_path_ids.append({
                            'url': endpoint,
                            'path_ids': path_ids,
                            'base_url': endpoint
                        })

                page.close()

            except Exception as e:
                print(f"{COLORS['YELLOW']}   ⚠ Error: {str(e)[:40]}{COLORS['RESET']}")
                continue

        print(f"\n{COLORS['GREEN']}✓{COLORS['RESET']} Crawled {len(self.visited_urls)} pages")
        print(
            f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.all_get_params)} endpoints with numeric ID parameters")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.all_path_ids)} endpoints with numeric IDs in path")
        print(f"{COLORS['GREEN']}✓{COLORS['RESET']} Found {len(self.api_endpoints)} API endpoints")

    def get_response_fast(self, url, context, method="GET", data=None):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }

            if method == "GET":
                response = context.request.get(url, headers=headers, timeout=5000)
            elif method == "POST":
                response = context.request.post(url, headers=headers, data=data, timeout=5000)
            elif method == "PUT":
                response = context.request.put(url, headers=headers, data=data, timeout=5000)
            elif method == "DELETE":
                response = context.request.delete(url, headers=headers, timeout=5000)
            else:
                response = context.request.get(url, headers=headers, timeout=5000)

            return response.status, response.text()
        except:
            return 0, None

    def test_idor_parameters_in_query(self, context):
        print(
            f"\n{COLORS['CYAN']}►{COLORS['RESET']} Testing Query Parameters for IDOR vulnerabilities...{COLORS['RESET']}\n")

        grouped_params = {}
        for param_data in self.all_get_params:
            base_url = param_data['base_url']
            if base_url not in grouped_params:
                grouped_params[base_url] = {
                    'params': param_data['params'].copy(),
                    'numeric_params': param_data['numeric_params'].copy()
                }
            else:
                grouped_params[base_url]['numeric_params'].update(param_data['numeric_params'])
                for k, v in param_data['params'].items():
                    if k not in grouped_params[base_url]['params']:
                        grouped_params[base_url]['params'][k] = v

        for base_url, data in grouped_params.items():
            params = data['params']
            numeric_params = data['numeric_params']

            original_data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            original_url = f"{base_url}?{urlencode(original_data)}"

            orig_status, orig_response = self.get_response_fast(original_url, context)
            if orig_status != 200 or not orig_response or len(orig_response) < 100:
                continue

            print(f"\n{COLORS['BLUE']}━━━ Testing Query ID Endpoint: {base_url}{COLORS['RESET']}")

            for param_key, orig_val in numeric_params.items():
                if isinstance(orig_val, list):
                    orig_val = orig_val[0]

                try:
                    orig_int = int(orig_val)
                except:
                    continue

                test_variations = [orig_int + 1, orig_int - 1, orig_int + 10, max(1, orig_int - 10), 1, 99999]

                for test_val in test_variations:
                    if str(test_val) == str(orig_val):
                        continue

                    test_params = original_data.copy()
                    test_params[param_key] = str(test_val)
                    test_url = f"{base_url}?{urlencode(test_params)}"

                    print(f"{COLORS['GRAY']}   Testing {param_key}={COLORS['YELLOW']}{test_val}{COLORS['RESET']}",
                          end=" ", flush=True)

                    self.total_tests += 1
                    status, test_response = self.get_response_fast(test_url, context)

                    if status == 200 and test_response and len(test_response) > 100:
                        if test_response != orig_response:
                            if self.is_sensitive_content(test_response) and not self.is_public_content(test_response):
                                self.vulnerable_tests += 1
                                print(f"{COLORS['RED']}⚠ REAL IDOR DETECTED!{COLORS['RESET']}")

                                vuln_data = {
                                    'type': 'Query Parameter - REAL IDOR',
                                    'original_url': original_url,
                                    'test_url': test_url,
                                    'parameter': param_key,
                                    'original_id': orig_val,
                                    'test_id': test_val,
                                    'status': status,
                                    'sensitive': True
                                }
                                self.real_idors.append(vuln_data)
                                self.idor_vulnerable.append(vuln_data)
                                self.send_instant_idor(vuln_data)
                                break
                            elif self.is_public_content(test_response):
                                self.false_positives += 1
                                print(f"{COLORS['DIM']}⚠ Public content{COLORS['RESET']}")
                            else:
                                print(f"{COLORS['YELLOW']}⚠ Different content (check manually){COLORS['RESET']}")
                                vuln_data = {
                                    'type': 'Query Parameter - Potential IDOR',
                                    'original_url': original_url,
                                    'test_url': test_url,
                                    'parameter': param_key,
                                    'original_id': orig_val,
                                    'test_id': test_val,
                                    'status': status,
                                    'sensitive': False
                                }
                                self.potential_idors.append(vuln_data)
                                self.idor_vulnerable.append(vuln_data)
                        else:
                            print(f"{COLORS['GREEN']}✓ Same content{COLORS['RESET']}")
                    elif status == 403 or status == 401:
                        print(f"{COLORS['DIM']}✓ Protected ({status}){COLORS['RESET']}")
                    else:
                        print(f"{COLORS['DIM']}✓ Status {status}{COLORS['RESET']}")

    def test_idor_parameters_in_path(self, context):
        print(
            f"\n{COLORS['CYAN']}►{COLORS['RESET']} Testing Path Parameters for IDOR vulnerabilities...{COLORS['RESET']}\n")

        for path_data in self.all_path_ids:
            url = path_data['url']
            path_ids = path_data['path_ids']

            orig_status, orig_response = self.get_response_fast(url, context)
            if orig_status != 200 or not orig_response or len(orig_response) < 100:
                continue

            print(f"\n{COLORS['BLUE']}━━━ Testing Path ID Endpoint: {url[:80]}...{COLORS['RESET']}")

            for id_info in path_ids:
                orig_val = id_info['value']
                orig_int = int(orig_val)
                path_parts = url.split('/')

                test_variations = [orig_int + 1, orig_int - 1, orig_int + 10, max(1, orig_int - 10), 1, 99999]

                for test_val in test_variations:
                    if str(test_val) == orig_val:
                        continue

                    test_parts = path_parts.copy()
                    test_parts[id_info['index']] = str(test_val)
                    test_url = '/'.join(test_parts)

                    print(f"{COLORS['GRAY']}   Testing path ID {COLORS['YELLOW']}{test_val}{COLORS['RESET']}",
                          end=" ", flush=True)

                    self.total_tests += 1
                    status, test_response = self.get_response_fast(test_url, context)

                    if status == 200 and test_response and len(test_response) > 100:
                        if test_response != orig_response:
                            if self.is_sensitive_content(test_response) and not self.is_public_content(test_response):
                                self.vulnerable_tests += 1
                                print(f"{COLORS['RED']}⚠ REAL IDOR DETECTED!{COLORS['RESET']}")

                                vuln_data = {
                                    'type': 'Path Parameter - REAL IDOR',
                                    'original_url': url,
                                    'test_url': test_url,
                                    'parameter': 'path_id',
                                    'original_id': orig_val,
                                    'test_id': test_val,
                                    'status': status,
                                    'sensitive': True
                                }
                                self.real_idors.append(vuln_data)
                                self.idor_vulnerable.append(vuln_data)
                                self.send_instant_idor(vuln_data)
                                break
                            elif self.is_public_content(test_response):
                                self.false_positives += 1
                                print(f"{COLORS['DIM']}⚠ Public content{COLORS['RESET']}")
                            else:
                                print(f"{COLORS['YELLOW']}⚠ Different content (check manually){COLORS['RESET']}")
                                vuln_data = {
                                    'type': 'Path Parameter - Potential IDOR',
                                    'original_url': url,
                                    'test_url': test_url,
                                    'parameter': 'path_id',
                                    'original_id': orig_val,
                                    'test_id': test_val,
                                    'status': status,
                                    'sensitive': False
                                }
                                self.potential_idors.append(vuln_data)
                                self.idor_vulnerable.append(vuln_data)
                        else:
                            print(f"{COLORS['GREEN']}✓ Same content{COLORS['RESET']}")
                    elif status == 403 or status == 401:
                        print(f"{COLORS['DIM']}✓ Protected ({status}){COLORS['RESET']}")
                    else:
                        print(f"{COLORS['DIM']}✓ Status {status}{COLORS['RESET']}")

    def test_forms_for_idor(self, context):
        print(f"\n{COLORS['CYAN']}►{COLORS['RESET']} Testing Forms for IDOR vulnerabilities...{COLORS['RESET']}\n")

        for form in self.all_forms:
            if form['method'] == 'POST':
                numeric_inputs = [inp for inp in form['inputs'] if inp['type'] in ['number', 'text']]
                if not numeric_inputs:
                    continue

                for inp in numeric_inputs:
                    print(f"\n{COLORS['BLUE']}━━━ Testing Form: {form['url'][:60]}...{COLORS['RESET']}")
                    print(f"{COLORS['GRAY']}   Testing field: {inp['name']}{COLORS['RESET']}")

                    test_values = [1, 2, 5, 10, 100, 99999]
                    for test_val in test_values:
                        data = {inp['name']: str(test_val)}

                        print(f"{COLORS['GRAY']}   Testing {inp['name']}={COLORS['YELLOW']}{test_val}{COLORS['RESET']}",
                              end=" ", flush=True)

                        self.total_tests += 1
                        status, test_response = self.get_response_fast(form['url'], context, "POST", data)

                        if status == 200 and test_response and len(test_response) > 100:
                            if self.is_sensitive_content(test_response) and not self.is_public_content(test_response):
                                self.vulnerable_tests += 1
                                print(f"{COLORS['RED']}⚠ REAL IDOR in FORM!{COLORS['RESET']}")
                                vuln_data = {
                                    'type': 'Form POST - REAL IDOR',
                                    'original_url': form['url'],
                                    'test_url': form['url'],
                                    'parameter': inp['name'],
                                    'test_id': test_val,
                                    'status': status,
                                    'sensitive': True
                                }
                                self.real_idors.append(vuln_data)
                                self.idor_vulnerable.append(vuln_data)
                                self.send_instant_idor(vuln_data)
                                break
                            elif self.is_public_content(test_response):
                                self.false_positives += 1
                                print(f"{COLORS['DIM']}⚠ Public content{COLORS['RESET']}")
                            else:
                                print(f"{COLORS['YELLOW']}⚠ Different content (check manually){COLORS['RESET']}")
                                vuln_data = {
                                    'type': 'Form POST - Potential IDOR',
                                    'original_url': form['url'],
                                    'test_url': form['url'],
                                    'parameter': inp['name'],
                                    'test_id': test_val,
                                    'status': status,
                                    'sensitive': False
                                }
                                self.potential_idors.append(vuln_data)
                                self.idor_vulnerable.append(vuln_data)
                        elif status == 403 or status == 401:
                            print(f"{COLORS['DIM']}✓ Protected ({status}){COLORS['RESET']}")
                        else:
                            print(f"{COLORS['DIM']}✓ Status {status}{COLORS['RESET']}")

    def print_final_results(self):
        real_idors = [v for v in self.idor_vulnerable if v.get('sensitive', False)]
        potential_idors = [v for v in self.idor_vulnerable if not v.get('sensitive', False)]

        print(f"\n{COLORS['CYAN']}╔══════════════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}📊 IDOR SCAN FINAL RESULTS{COLORS['RESET']}                                   {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}                                                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}Pages Discovered:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.discovered_urls)}{COLORS['RESET']}                                    {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}Query ID Endpoints:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.all_get_params)}{COLORS['RESET']}                                {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}Path ID Endpoints:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.all_path_ids)}{COLORS['RESET']}                                  {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}API Endpoints:{COLORS['RESET']} {COLORS['YELLOW']}{len(self.api_endpoints)}{COLORS['RESET']}                                      {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}Total Variations Tested:{COLORS['RESET']} {COLORS['YELLOW']}{self.total_tests}{COLORS['RESET']}                           {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}False Positives Filtered:{COLORS['RESET']} {COLORS['YELLOW']}{self.false_positives}{COLORS['RESET']}                                 {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}Potential IDORs Found:{COLORS['RESET']} {COLORS['YELLOW']}{len(potential_idors)}{COLORS['RESET']}                                 {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}    {COLORS['DIM']}✅ Real IDORs Found:{COLORS['RESET']} {COLORS['RED']}{len(real_idors)}{COLORS['RESET']}                                   {COLORS['CYAN']}║{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']}                                                              {COLORS['CYAN']}║{COLORS['RESET']}")

        if real_idors:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['RED']}🚨 {COLORS['BOLD']}REAL IDOR VULNERABILITIES:{COLORS['RESET']}                               {COLORS['CYAN']}║{COLORS['RESET']}")
            for idx, vuln in enumerate(real_idors, 1):
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['RED']}{idx}.{COLORS['RESET']} [{vuln['type']}] {COLORS['YELLOW']}{vuln['test_url'][:45]}...{COLORS['RESET']}     {COLORS['CYAN']}║{COLORS['RESET']}")
                if 'parameter' in vuln:
                    print(
                        f"{COLORS['CYAN']}║{COLORS['RESET']}      {COLORS['DIM']}Param:{COLORS['RESET']} {COLORS['MAGENTA']}{vuln['parameter']}{COLORS['RESET']} | Swapped {vuln.get('original_id', 'N/A')} -> {vuln['test_id']}{COLORS['RESET']}        {COLORS['CYAN']}║{COLORS['RESET']}")
        elif potential_idors:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['YELLOW']}⚠ {COLORS['BOLD']}POTENTIAL IDOR ENDPOINTS (Check Manually):{COLORS['RESET']}                 {COLORS['CYAN']}║{COLORS['RESET']}")
            for idx, vuln in enumerate(potential_idors[:5], 1):
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}   {COLORS['YELLOW']}{idx}.{COLORS['RESET']} [{vuln['type']}] {COLORS['GRAY']}{vuln['test_url'][:40]}...{COLORS['RESET']}      {COLORS['CYAN']}║{COLORS['RESET']}")
            if len(potential_idors) > 5:
                print(
                    f"{COLORS['CYAN']}║{COLORS['RESET']}      {COLORS['DIM']}... and {len(potential_idors) - 5} more potential IDORs{COLORS['RESET']}                    {COLORS['CYAN']}║{COLORS['RESET']}")
        else:
            print(
                f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['GREEN']}✓ No IDOR Vulnerabilities Found                        {COLORS['RESET']}  {COLORS['CYAN']}║{COLORS['RESET']}")

        print(f"{COLORS['CYAN']}╚══════════════════════════════════════════════════════════════╝{COLORS['RESET']}")

        self.send_final_summary()

    def run_scan(self, target_url):
        self.base_url = target_url

        print(f"\n{COLORS['CYAN']}╔═════════════════════════════════════════════════════╗{COLORS['RESET']}")
        print(
            f"{COLORS['CYAN']}║{COLORS['RESET']} {COLORS['BOLD']}🔍 Starting IDOR Scan {COLORS['RESET']}                              {COLORS['CYAN']}║{COLORS['RESET']}")
        print(f"{COLORS['CYAN']}╚═════════════════════════════════════════════════════╝{COLORS['RESET']}")

        with sync_playwright() as p:
            print(f"{COLORS['CYAN']}►{COLORS['RESET']} Initializing browser...")
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            print(f"{COLORS['CYAN']}►{COLORS['RESET']} Loading target: {COLORS['YELLOW']}{target_url}{COLORS['RESET']}")

            try:
                page.goto(target_url, timeout=30000)
                page.wait_for_load_state("networkidle", timeout=15000)
                time.sleep(2)
            except Exception as e:
                print(f"{COLORS['YELLOW']}⚠ Page load warning: {str(e)[:50]}{COLORS['RESET']}")

            self.discover_pages(page)
            self.crawl_pages(context)

            self.test_idor_parameters_in_query(context)
            self.test_idor_parameters_in_path(context)
            self.test_forms_for_idor(context)

            self.print_final_results()
            browser.close()

    def main(self):
        self.print_banner()
        print("\033[1;30m" + "=" * 60 + "\033[0m")
        print("")
        url = input(f"└──> {COLORS['BOLD']}Enter target URL :{COLORS['RESET']}").strip()
        if not url.startswith("http"):
            url = "https://" + url

        self.run_scan(url)
        sys.exit(0)


if __name__ == "__main__":
    scanner = IDORScanner()
    scanner.main()
