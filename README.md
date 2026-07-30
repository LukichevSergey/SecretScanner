# 🛡️ SecretScanner (SecretFinder)

> **Production-grade secret audit & sensitive data scanner for iOS/macOS (Xcode/Swift) and cross-platform projects.**
> Designed specifically for auditing codebases **before** sharing them with cloud AI assistants (*Claude Code, Gemini CLI, OpenAI Codex, GitHub Copilot, Cursor, etc.*).

---

## 🚀 Overview

**SecretScanner** combines the power of **Gitleaks**, **TruffleHog**, and **Detect Secrets** into a single, high-performance Python 3.12+ engine with deep, dedicated rules for **iOS, macOS, Swift, and Xcode** environments.

It scans files, directory structures, and complete **Git histories** (*commits, branches, tags, stashes, and deleted files*) to prevent accidental leakage of proprietary API keys, private certificates, database URIs, and credentials.

---

## ✨ Features

- 🖥️ **Desktop GUI Application**: Built-in graphical user interface (Tkinter / macOS native look) featuring project folder selection, custom file/directory exclusion controls, scan options, live progress logs, and a button to open interactive HTML reports in the browser.
- 📱 **iOS/macOS & Swift First**: Audits `GoogleService-Info.plist`, `.p8` Apple AuthKeys, `.mobileprovision` profiles, `.p12` certificates, `Fastfile`/`Matchfile`, `.xcconfig`, `.entitlements`, and Swift string variable assignments.
- 🔑 **Comprehensive API & Service Detection**: Detects keys for OpenAI, Anthropic, Google, AWS, Azure, GitHub, GitLab, Stripe, RevenueCat, OneSignal, Branch, Amplitude, Mixpanel, AppsFlyer, Sentry, Mapbox, Twilio, SendGrid, Supabase, Cloudflare, Databases (Postgres, MongoDB, Redis), JWT, Bearer tokens, and SSH keys.
- 🧮 **Shannon Entropy Analysis**: Identifies high-entropy unquoted or quoted strings (> 20 chars) while avoiding false positives (UUIDs, SHA hashes, URLs, bundle identifiers).
- 📜 **Full Git History Audit**: Scans historical commits, uncommitted working tree diffs, stashes, tags, and deleted files.
- ⚡ **High Performance Concurrent Architecture**: Multi-threaded scanning utilizing `concurrent.futures` for lightning-fast auditing.
- 📊 **Multi-Format Report Generation**: Outputs interactive `report.html`, structured `report.json`, GitHub-flavored `report.md`, and plain `report.txt`.

---

## 📥 Download (macOS)

Grab the ready-to-run desktop app — no Python setup required:

**[⬇️ Download SecretScanner.dmg](https://github.com/LukichevSergey/SecretScanner/releases/latest)**

Open the `.dmg`, drag **SecretScanner** into `Applications`, and launch it. macOS may ask you to confirm opening an app from an unidentified developer on first launch (right-click → Open).

---

## 🛠️ Installation & Requirements (running from source)

- **Python Version**: Python 3.12+ (compatible with Python 3.9+)
- **Dependencies**: Built purely with standard Python libraries (`tkinter`, `dataclasses`, `pathlib`, `concurrent.futures`, `re`, `json`, `subprocess`). No mandatory 3rd party packages required!
- **GUI note**: on macOS, use a Python build with Tk 8.6+ (e.g. Homebrew's `python-tk`) — very old system Tk (8.5) fails to render the desktop UI correctly.

---

## 🖥️ Graphical User Interface (Desktop App)

To launch the desktop GUI application:

```bash
python3 scanner.py
# Or explicitly:
python3 scanner.py --gui
```

### Features of the Desktop App:
1. **Target Folder Picker**: Select any iOS/macOS Xcode project directory using macOS native folder dialog.
2. **Custom Exclusions Input**:
   - **Excluded Directories**: Add custom folders to skip (e.g. `DerivedData, Pods, Carthage, build, MyExcludedFolder`).
   - **Excluded Files**: Add custom files or patterns to ignore (e.g. `Podfile.lock, MySecretsMock.swift, *.testdata`).
3. **Interactive Control & Options**: Toggle Git history analysis, adjust Shannon entropy thresholds, and control thread counts.
4. **Live Execution Console**: Real-time log output displaying progress, findings breakdown, and errors.
5. **One-Click HTML Report Viewer**: Opens `report.html` directly in your default browser.


```bash
git clone https://github.com/LukichevSergey/SecretScanner.git
cd SecretScanner
```

---

## 💻 Usage

### 1. Launch with GUI Folder Picker
If no path argument is provided, SecretScanner opens a directory selector window:

```bash
python scanner.py
```

### 2. Scan a Specific Project Path
```bash
python scanner.py /Users/developer/Projects/MyAwesomeiOSApp
```

### 3. Advanced CLI Options
```bash
python scanner.py /path/to/project \
  --output-dir ./audit_results \
  --entropy-threshold 4.8 \
  --workers 16 \
  --no-git
```

#### Available Flags:
| Argument | Description | Default |
| :--- | :--- | :--- |
| `path` | Path to target project directory | Opens Tkinter GUI if omitted |
| `-c`, `--config` | Custom JSON configuration file | None |
| `-o`, `--output-dir` | Directory where report artifacts are saved | Project Directory |
| `--no-git` | Disable Git commit history and stash scanning | `False` |
| `--no-entropy` | Disable Shannon entropy analysis | `False` |
| `--entropy-threshold` | Cutoff Shannon entropy bits per character | `4.5` |
| `-w`, `--workers` | Maximum concurrent thread pool workers | `8` |

---

## 📁 Project Architecture

```
SecretFinder/
├── scanner.py                 # Root entrypoint launcher
├── secret_scanner/
│   ├── __init__.py
│   ├── models.py              # Strongly typed Dataclasses & RiskLevel Enums
│   ├── config.py              # Configuration manager & default exclusions
│   ├── patterns.py            # API/Service regex rules & Swift assignments
│   ├── entropy.py             # Shannon entropy & candidate extraction
│   ├── git_scanner.py         # Full Git history, diff, and stash scanner
│   ├── file_scanner.py        # Multi-threaded filesystem scanner
│   ├── scanner.py             # Core Engine Orchestrator
│   ├── cli.py                 # CLI parser & Tkinter GUI fallback
│   ├── utils.py               # Redaction, binary detection & context slicing
│   ├── report_json.py         # JSON report generator
│   ├── report_html.py         # Dynamic interactive HTML dashboard
│   ├── report_markdown.py     # GitHub-Flavored Markdown generator
│   └── report_console.py      # Console summary dashboard & text report
├── tests/                     # Comprehensive Unit Test Suite
│   ├── test_entropy.py
│   ├── test_patterns.py
│   ├── test_file_scanner.py
│   ├── test_reports.py
│   └── ...
├── requirements.txt
└── README.md
```

---

## 🔍 What SecretScanner Audits

### 1. iOS / macOS & Xcode Specific
- `GoogleService-Info.plist` (Google API Keys, DB URLs)
- Apple AuthKeys (`AuthKey_*.p8`)
- Provisioning Profiles (`.mobileprovision`)
- PKCS#12 Certificates & Keys (`.p12`, `.pfx`, `.pem`, `.key`, `.keystore`)
- Fastlane Assets (`Fastfile`, `Appfile`, `Matchfile`)
- Xcode Build Configs (`.xcconfig`, `.entitlements`)
- Sensitive Swift Files (`Secrets.swift`, `LocalConfig.swift`, `Config.swift`)
- Swift string assignments (`password`, `secret`, `token`, `clientSecret`, `privateKey`, `accessToken`, `authorization`, `bearer`, `apikey`, `jwt`, `credential`, etc.)
- Database files (`.sqlite`, `.realm`, CoreData SQLite databases, log files, crash dumps)

### 2. Cloud & API Keys
- **AI Services**: OpenAI, Anthropic Claude, Google Gemini
- **Cloud Providers**: AWS Access/Secret Keys, Azure Connection Strings, Google Cloud, Supabase, Cloudflare, DigitalOcean
- **Developer Services**: GitHub (PATs/Tokens), GitLab, Bitbucket, Sentry, Bugsnag, Mapbox, HERE, Algolia, Twilio, SendGrid
- **Mobile Analytics & Monetization**: RevenueCat, OneSignal, Branch.io, Stripe, Amplitude, Mixpanel, AppsFlyer, Adjust
- **Databases & Queues**: PostgreSQL, MongoDB Atlas, Redis, Elasticsearch, RabbitMQ, Kafka URIs

---

## 📊 Reports Generated

After completing an audit scan, SecretScanner creates 4 report files in the output directory:

1. **`report.html`**: A dark-mode interactive HTML report featuring real-time search, risk filter badges, and collapsible **20-line surrounding code context windows**.
2. **`report.json`**: Machine-readable JSON structured data for CI/CD integration.
3. **`report.md`**: Clean Markdown documentation with executive summary tables and remediation recommendations.
4. **`report.txt`**: Plain text audit overview.

---

## 🧪 Running Unit Tests

Run the complete test suite using Python's standard `unittest`:

```bash
python3 -m unittest discover -s tests
```

Or with `pytest`:

```bash
pytest tests/
```

---

## 📄 License

Open-source under the MIT License.
