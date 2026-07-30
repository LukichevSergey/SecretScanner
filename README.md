# 🛡️ SecretScanner (SecretFinder)

> **Production-grade secret audit & sensitive data scanner for mobile (iOS + Android) and cross-platform projects.**
> Designed specifically for auditing codebases **before** sharing them with cloud AI assistants (*Claude Code, Gemini CLI, OpenAI Codex, GitHub Copilot, Cursor, etc.*).

---

## 🚀 Overview

**SecretScanner** combines the power of **Gitleaks**, **TruffleHog**, and **Detect Secrets** into a single, high-performance Python engine with deep, dedicated rules for **iOS/Swift/Xcode** *and* **Android/Kotlin/Gradle**, plus the common web and backend stacks.

It scans files, directory structures, and complete **Git histories** (*commits, branches, tags, stashes, and deleted files*) to prevent accidental leakage of proprietary API keys, private certificates, database URIs, and credentials.

---

## ✨ Features

- 🖥️ **Desktop GUI Application**: Cyberpunk-themed Tkinter interface with project folder selection, exclusion controls, scan options, live progress logs, and one-click HTML report opening. Runs on **macOS and Windows**.
- 📱 **iOS & Android, Equally**:
  - *Apple*: `GoogleService-Info.plist`, `.p8` AuthKeys, `.mobileprovision`, `.p12`, `Fastfile`/`Matchfile`, `.xcconfig`, `.entitlements`, Swift assignments, Objective-C `#define` macros.
  - *Android*: `local.properties`, `gradle.properties`, `keystore.properties`, signing credentials (`storePassword`/`keyAlias`), `google-services.json`, `buildConfigField`, Android string resources, Maps keys in `AndroidManifest.xml`.
- 🧠 **Name-aware detection**: Catches secrets by *identifier name*, not just value shape — `MAPKIT_API_KEY = "0000…-4444"` is flagged even though a UUID has low entropy. Prefixed and camelCase names (`yandexApiKey`, `MY_APP_CLIENT_SECRET`) are covered, while lookalikes such as `tokenizer` or `keyPath` are not.
- 🔑 **55+ built-in provider rules**: OpenAI, Anthropic, Hugging Face, Google/Firebase, AWS, Azure, Cloudflare, DigitalOcean, Supabase, GitHub, GitLab, npm, PyPI, Stripe, PayPal/Braintree, Square, RevenueCat, Mapbox, Yandex MapKit, 2GIS/HERE, Sentry, OneSignal, Amplitude, Mixpanel, AppsFlyer/Adjust/Branch, AppMetrica/VK, Slack, Telegram, Twilio, SendGrid, Discord, FCM, Postgres/MySQL/Mongo/Redis/JDBC, JWT, Bearer/Basic auth, SSH/PGP/RSA keys.
- ⚙️ **Configurable rules UI**: Turn any individual check on or off, add your own **sensitive keywords** (no regex knowledge needed), or write full **custom regex rules** — all persisted between sessions.
- 🧮 **Shannon Entropy Analysis**: Identifies high-entropy strings while filtering known false positives (URLs, SHA hashes, bundle identifiers).
- 📜 **Full Git History Audit**: Scans historical commits, uncommitted working tree diffs, stashes, tags, and deleted files.
- ⚡ **High Performance Concurrent Architecture**: Multi-threaded scanning with a rule set compiled once and shared across all files.
- 📊 **Multi-Format Report Generation**: Interactive `report.html`, structured `report.json`, GitHub-flavored `report.md`, plain `report.txt`, with an optional **brief mode** that omits code context.

---

## 📥 Download

Ready-to-run desktop apps — no Python setup required. Get them from the
**[latest release](https://github.com/LukichevSergey/SecretScanner/releases/latest)**:

| Platform | File | How to run |
| :--- | :--- | :--- |
| macOS 11+ | `SecretScanner-macos.dmg` | Open the DMG, drag **SecretScanner** into `Applications`. On first launch right-click → **Open** (the app is unsigned). |
| Windows 10+ | `SecretScanner-windows.zip` | Unzip and run `SecretScanner.exe`. SmartScreen may warn on first run → **More info** → **Run anyway** (the app is unsigned). |

Both builds are produced automatically by [GitHub Actions](.github/workflows/release.yml) from the tagged source.

---

## 🛠️ Installation & Requirements (running from source)

- **Python Version**: Python 3.12+ recommended (compatible with Python 3.9+)
- **Dependencies**: Built purely with standard Python libraries (`tkinter`, `dataclasses`, `pathlib`, `concurrent.futures`, `re`, `json`, `subprocess`). No mandatory 3rd party packages required!
- **GUI note**: use a Python build with Tk 8.6+. On macOS the very old system Tk 8.5 shipped with Xcode's Python fails to render the interface — install Homebrew's `python-tk` (`brew install python-tk`) and launch with that interpreter.

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
4. **Brief Report Mode**: Toggle "Краткий отчёт" to strip the 20-line before/after code context and keep only the matched secret line — useful for smaller, easier-to-skim reports.
5. **Rules Window** (`⚙ ПРАВИЛА ПОИСКА`): Enable or disable each of the built-in checks individually, grouped by category with risk badges. Add project-specific **keywords** (e.g. `mapkit`, `widgetly`) so any identifier containing them is audited, or add **custom regex rules** with a name and risk level — invalid regexes are rejected with an inline error.
6. **Live Execution Console**: Real-time log output displaying progress, findings breakdown, and errors.
7. **One-Click HTML Report Viewer**: Opens `report.html` directly in your default browser.
8. **Persistent Settings**: Every field, checkbox and rule choice is remembered across restarts, stored in `~/.secretscanner/gui_settings.json` (override the location with the `SECRETSCANNER_SETTINGS` environment variable).


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
│   ├── patterns.py            # Provider rules, name-based detection, custom rules
│   ├── entropy.py             # Shannon entropy & candidate extraction
│   ├── git_scanner.py         # Full Git history, diff, and stash scanner
│   ├── file_scanner.py        # Multi-threaded filesystem scanner
│   ├── scanner.py             # Core Engine Orchestrator
│   ├── cli.py                 # CLI parser & Tkinter GUI fallback
│   ├── gui.py                 # Desktop console + rules configuration window
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
- Swift/Objective-C assignments and `#define` macros holding keys, tokens or passwords
- App Store Connect / Fastlane API credentials
- Database files (`.sqlite`, `.realm`, CoreData SQLite databases, log files, crash dumps)

### 2. Android / Kotlin / Gradle Specific
- Release signing credentials — `storePassword`, `keyPassword`, `keyAlias`, `storeFile`
- `local.properties`, `gradle.properties`, `keystore.properties`, `signing.properties`
- `google-services.json`, `agconnect-services.json` (Huawei)
- `buildConfigField("String", "API_KEY", …)` literals baked into `BuildConfig`
- Secrets in Android string resources (`res/values/*.xml`) — trivially extractable from an APK
- Google Maps keys declared in `AndroidManifest.xml` (`com.google.android.geo.API_KEY`)
- Kotlin/Java assignments (`const val`, `static final String`) holding keys or tokens
- Keystores (`.jks`, `.keystore`) and ProGuard configs

### 3. Cloud & API Keys
- **AI Services**: OpenAI, Anthropic Claude, Google Gemini
- **Cloud Providers**: AWS Access/Secret Keys, Azure Connection Strings, Google Cloud, Supabase, Cloudflare, DigitalOcean
- **Developer Services**: GitHub (PATs/Tokens), GitLab, Bitbucket, Sentry, Bugsnag, Mapbox, HERE, Algolia, Twilio, SendGrid
- **Mobile Analytics & Monetization**: RevenueCat, OneSignal, Branch.io, Stripe, Amplitude, Mixpanel, AppsFlyer, Adjust
- **Databases & Queues**: PostgreSQL, MongoDB Atlas, Redis, Elasticsearch, RabbitMQ, Kafka URIs

---

## 📦 Building the Apps Yourself

Both binaries on the [Releases page](https://github.com/LukichevSergey/SecretScanner/releases) are produced by the
[`Build & Release`](.github/workflows/release.yml) workflow, which runs the test suite and then builds on
`macos-latest` and `windows-latest`. Push a `v*` tag (or run the workflow manually with a tag) and the
artifacts are attached to that release automatically.

To build locally:

**macOS** (`py2app` → `.app` → `.dmg`):

```bash
python3 -m venv .build-venv
.build-venv/bin/pip install py2app
.build-venv/bin/python setup.py py2app
```

**Windows** (`PyInstaller` → single `.exe`) — must be run *on* Windows, PyInstaller does not cross-compile:

```bash
pip install pyinstaller
pyinstaller --noconfirm SecretScanner.spec
```

Use a Python with Tk 8.6+ (see the GUI note above) so the bundled app renders correctly.

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
