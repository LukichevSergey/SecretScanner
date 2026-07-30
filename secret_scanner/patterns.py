"""
Regex pattern rules engine for SecretScanner.
Includes Gitleaks, TruffleHog, and mobile (iOS/Swift/Xcode, Android/Kotlin/Gradle)
specific security audit rules, plus cross-platform web and backend providers.
"""

from __future__ import annotations

from typing import Iterable, List, Optional
from secret_scanner.models import PatternRule, RiskLevel


# ---------------------------------------------------------------------------
# Building blocks for name-based ("the variable name says it's a secret") rules
# ---------------------------------------------------------------------------
#
# Case sensitivity is applied per-fragment with (?i:...) instead of a global
# (?i) flag: the name tail below relies on [A-Z] staying case-SENSITIVE so that
# `accessTokenValue` matches while `tokenizer` does not.

# Ordered longest-first so that `secret_key` wins over the shorter `secret`.
SECRET_WORDS = (
    r"api[_\-]?key|api[_\-]?secret|api[_\-]?token|"
    r"access[_\-]?key|access[_\-]?token|secret[_\-]?key|secret[_\-]?token|"
    r"private[_\-]?key|public[_\-]?key[_\-]?secret|encryption[_\-]?key|"
    r"signing[_\-]?key|master[_\-]?key|session[_\-]?key|"
    r"client[_\-]?secret|client[_\-]?key|consumer[_\-]?secret|"
    r"refresh[_\-]?token|auth[_\-]?token|id[_\-]?token|bearer[_\-]?token|"
    r"licen[cs]e[_\-]?key|subscription[_\-]?key|"
    r"app[_\-]?secret|app[_\-]?key|sdk[_\-]?key|"
    r"authorization|credentials?|passphrase|password|passwd|"
    r"secret|token"
)

# Value substrings that are obviously not real secrets.
JUNK_VALUES = (
    r"true|false|null|nil|none|nan|undefined|yes|no|"
    r"bearer|basic|oauth|jwt|utf-?8|application/json|"
    r"debug|release|staging|production|development|localhost|"
    r"string|integer|boolean|number|object|array|"
    r"your[_\-a-z0-9]*|my[_\-a-z0-9]*|some[_\-a-z0-9]*|"
    r"change[_\-]?me|todo|tbd|fixme|x{3,}|\*{3,}|\.{3,}|_{3,}|-{3,}|"
    r"placeholder[_\-a-z0-9]*|example[_\-a-z0-9]*|sample[_\-a-z0-9]*|"
    r"dummy[_\-a-z0-9]*|redacted|hidden|unknown|default|empty|"
    r"password|passw0rd|secret|token|apikey|api[_\-]key|"
    r"insert[_\-a-z0-9]*|enter[_\-a-z0-9]*|replace[_\-a-z0-9]*"
)

# An identifier that *contains* a secret word, e.g. MAPKIT_API_KEY, yandexApiKey.
# Prefix is free-form; the tail only accepts separator- or CamelCase-delimited
# continuations so that `tokenizer` is not mistaken for a `token` assignment.
_NAME_PREFIX = r"[A-Za-z0-9_.\-]{0,40}"
_NAME_TAIL = r"(?:[_\-]?[A-Z][A-Za-z0-9]{0,20}){0,3}"

# Optional type annotation + assignment operator: `= `, `: `, `: String = `.
_ASSIGN = r"[\"']?\s*(?::\s*[A-Za-z_][A-Za-z0-9_<>\[\],.?\s]{0,40})?\s*(?:=|:)\s*"

# A quoted literal that is not an obvious placeholder or string interpolation.
_QUOTED_VALUE = (
    r"[\"'`]"
    r"(?!(?i:" + JUNK_VALUES + r")[\"'`])"
    r"(?![$<{@%])"
    r"([^\s\"'`()]{4,200})"
    r"[\"'`]"
)


def build_name_assignment_pattern(words: str) -> str:
    """Build a 'sensitive identifier = quoted literal' regex from a word alternation."""
    return (
        r"\b" + _NAME_PREFIX + r"(?i:" + words + r")" + _NAME_TAIL + _ASSIGN + _QUOTED_VALUE
    )


def build_custom_keyword_rule(keywords: Iterable[str]) -> Optional[PatternRule]:
    """
    Build a single rule from user-supplied sensitive keywords.

    Lets users catch project-specific names (e.g. `mapkit`, `yandex`) without
    writing a regex: any identifier containing the keyword and assigned a
    quoted literal is reported.
    """
    import re as _re

    cleaned = [k.strip() for k in keywords if k and k.strip()]
    if not cleaned:
        return None

    alternation = "|".join(_re.escape(k) for k in sorted(set(cleaned), key=len, reverse=True))
    return PatternRule(
        id="CUSTOM-KEYWORDS",
        name="Custom Sensitive Keyword",
        pattern=build_name_assignment_pattern(alternation),
        risk_level=RiskLevel.HIGH,
        description="Identifier matching a user-defined sensitive keyword is assigned a hardcoded literal.",
        recommendation="Move this value out of source code into a secure store or build-time configuration.",
        category="Custom",
    )


def resolve_active_rules(config) -> List[PatternRule]:
    """
    Build the effective rule set for a scan.

    Starts from the built-in rules, drops the ones the user switched off,
    then appends the user's own keyword rule and custom regex rules.
    """
    disabled = set(getattr(config, "disabled_rule_ids", ()) or ())
    rules = [r for r in get_all_rules() if r.id not in disabled]

    keyword_rule = build_custom_keyword_rule(getattr(config, "custom_keywords", ()) or ())
    if keyword_rule and keyword_rule.id not in disabled:
        rules.append(keyword_rule)

    for custom in getattr(config, "custom_rules", ()) or ():
        if custom.id not in disabled:
            rules.append(custom)

    return rules


def get_all_rules() -> List[PatternRule]:
    """Return the complete list of built-in pattern detection rules."""

    rules: List[PatternRule] = [
        # ------------------------------------------------------------------
        # AI providers
        # ------------------------------------------------------------------
        PatternRule(
            id="API-001",
            name="OpenAI API Key",
            pattern=r"\bsk-(?:proj-|admin-)?[a-zA-Z0-9_-]{32,64}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected OpenAI API key or Project secret key.",
            recommendation="Revoke the API key in OpenAI Dashboard and move it to environment variables or Keychain.",
            category="AI",
        ),
        PatternRule(
            id="API-002",
            name="Anthropic API Key",
            pattern=r"\bsk-ant-api\d{2}-[a-zA-Z0-9_-]{80,120}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Anthropic Claude API key.",
            recommendation="Revoke key in Anthropic Console immediately.",
            category="AI",
        ),
        PatternRule(
            id="API-016",
            name="Hugging Face Access Token",
            pattern=r"\bhf_[a-zA-Z0-9]{30,40}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Hugging Face user access token.",
            recommendation="Revoke the token in Hugging Face account settings.",
            category="AI",
        ),
        PatternRule(
            id="API-017",
            name="Google Gemini / PaLM Key",
            pattern=r"\bAIzaSy[0-9A-Za-z_\-]{33}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Google AI (Gemini/PaLM) or Firebase API key.",
            recommendation="Restrict the key in Google Cloud Console and move it out of client code.",
            category="AI",
        ),

        # ------------------------------------------------------------------
        # Cloud providers
        # ------------------------------------------------------------------
        PatternRule(
            id="API-003",
            name="Google API Key",
            pattern=r"\bAIza[0-9A-Za-z_\-]{35}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Google Cloud / Firebase API key.",
            recommendation="Restrict API key permissions in Google Cloud Console or store in secure Keychain.",
            category="Cloud",
        ),
        PatternRule(
            id="API-004",
            name="AWS Access Key ID",
            pattern=r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected AWS Access Key ID.",
            recommendation="Check IAM policies, rotate key pair, and store in AWS Secrets Manager.",
            category="Cloud",
        ),
        PatternRule(
            id="API-005",
            name="AWS Secret Access Key",
            pattern=r"(?i)\baws_?(?:secret)?_?(?:access)?_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            risk_level=RiskLevel.CRITICAL,
            description="Detected AWS Secret Access Key.",
            recommendation="Immediately rotate AWS IAM credentials.",
            category="Cloud",
        ),
        PatternRule(
            id="API-018",
            name="Azure Storage Connection String",
            pattern=r"(?i)DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,}",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Azure Storage account connection string with embedded account key.",
            recommendation="Rotate the storage account key and use Managed Identity or Key Vault.",
            category="Cloud",
        ),
        PatternRule(
            id="API-019",
            name="Azure AD Client Secret",
            pattern=r"(?i)\b(?:azure|aad|msal)[a-z0-9_\-]{0,20}client[_\-]?secret\s*[:=]\s*[\"']([^\"'\s]{20,})[\"']",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Azure Active Directory application client secret.",
            recommendation="Rotate the client secret in Azure Portal and store it in Key Vault.",
            category="Cloud",
        ),
        PatternRule(
            id="API-020",
            name="Cloudflare API Token",
            pattern=r"(?i)\bcloudflare[a-z0-9_\-]{0,20}(?:api)?[_\-]?(?:token|key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{37,45})[\"']",
            risk_level=RiskLevel.HIGH,
            description="Detected Cloudflare API token or global API key.",
            recommendation="Roll the token in the Cloudflare dashboard.",
            category="Cloud",
        ),
        PatternRule(
            id="API-021",
            name="DigitalOcean Personal Access Token",
            pattern=r"\bdop_v1_[a-f0-9]{64}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected DigitalOcean personal access token.",
            recommendation="Revoke the token in the DigitalOcean API settings.",
            category="Cloud",
        ),
        PatternRule(
            id="API-015",
            name="Supabase Service Key",
            pattern=r"\bsbp_[a-f0-9]{40}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Supabase Service Role Key.",
            recommendation="Service role keys bypass RLS. Move to secure backend server.",
            category="Cloud",
        ),
        PatternRule(
            id="API-022",
            name="Firebase Realtime Database URL",
            pattern=r"\bhttps://[a-z0-9\-]{3,60}(?:-default-rtdb)?\.(?:firebaseio\.com|[a-z0-9\-]+\.firebasedatabase\.app)\b",
            risk_level=RiskLevel.LOW,
            description="Detected Firebase Realtime Database endpoint.",
            recommendation="Confirm database security rules deny unauthenticated access.",
            category="Cloud",
        ),

        # ------------------------------------------------------------------
        # Version control & CI/CD
        # ------------------------------------------------------------------
        PatternRule(
            id="API-006",
            name="GitHub Personal Access Token",
            pattern=r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected GitHub Personal Access Token.",
            recommendation="Revoke token in GitHub Settings > Developer settings > Access tokens.",
            category="VCS & CI",
        ),
        PatternRule(
            id="API-007",
            name="GitLab Personal Access Token",
            pattern=r"\bglpat-[a-zA-Z0-9_\-]{20,30}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected GitLab Personal Access Token.",
            recommendation="Revoke token in GitLab User Settings > Access Tokens.",
            category="VCS & CI",
        ),
        PatternRule(
            id="API-023",
            name="npm Access Token",
            pattern=r"\bnpm_[a-zA-Z0-9]{36}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected npm registry access token.",
            recommendation="Revoke the token with `npm token revoke` and avoid committing .npmrc.",
            category="VCS & CI",
        ),
        PatternRule(
            id="API-024",
            name="PyPI Upload Token",
            pattern=r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected PyPI API upload token.",
            recommendation="Revoke the token in PyPI account settings.",
            category="VCS & CI",
        ),
        PatternRule(
            id="API-025",
            name="Generic CI Credential in URL",
            pattern=r"\bhttps?://[A-Za-z0-9_.\-]{2,40}:[^@\s/]{6,}@[A-Za-z0-9.\-]+",
            risk_level=RiskLevel.CRITICAL,
            description="Detected credentials embedded in an HTTP(S) URL.",
            recommendation="Remove inline credentials; use a credential helper or CI secret.",
            category="VCS & CI",
        ),

        # ------------------------------------------------------------------
        # Payments & monetization
        # ------------------------------------------------------------------
        PatternRule(
            id="API-008",
            name="Stripe Secret Key",
            pattern=r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Stripe API Secret Key.",
            recommendation="Roll key in Stripe Developer Dashboard.",
            category="Payments",
        ),
        PatternRule(
            id="API-009",
            name="RevenueCat API Key",
            pattern=r"\b(?:appl|goog|amzn|rcb)_[a-zA-Z0-9]{32,64}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected RevenueCat API Key.",
            recommendation="Verify RevenueCat key scope and do not expose secret key in client app binary.",
            category="Payments",
        ),
        PatternRule(
            id="API-026",
            name="PayPal / Braintree Access Token",
            pattern=r"\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected PayPal Braintree access token.",
            recommendation="Revoke the token in the Braintree control panel.",
            category="Payments",
        ),
        PatternRule(
            id="API-027",
            name="Square Access Token",
            pattern=r"\b(?:sq0atp|sq0csp|EAAA)[a-zA-Z0-9_\-]{22,60}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Square access token or application secret.",
            recommendation="Rotate credentials in the Square Developer Dashboard.",
            category="Payments",
        ),

        # ------------------------------------------------------------------
        # Maps & geo (incl. Yandex MapKit, which uses UUID-shaped keys)
        # ------------------------------------------------------------------
        PatternRule(
            id="API-014",
            name="Mapbox Access Token",
            pattern=r"\b[ps]k\.eyJ1I[a-zA-Z0-9._\-]{50,150}\b",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Mapbox Public or Secret Token.",
            recommendation="Restrict token scopes or move secret tokens out of client code.",
            category="Maps & Geo",
        ),
        PatternRule(
            id="MAP-001",
            name="Yandex MapKit / API Key (UUID form)",
            pattern=(
                r"(?i)\b[a-z0-9_.\-]{0,40}(?:mapkit|yandex|ymaps|geocoder|geosuggest)[a-z0-9_.\-]{0,40}"
                r"[\"']?\s*(?::\s*[a-z_][a-z0-9_<>\[\]?.\s]{0,40})?\s*[:=]\s*"
                r"[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{8,12})[\"']"
            ),
            risk_level=RiskLevel.HIGH,
            description="Detected Yandex MapKit / Maps API key. These keys are UUID-shaped and are missed by entropy analysis.",
            recommendation="Restrict the key by app bundle id in the Yandex Developer Cabinet and load it from build configuration.",
            category="Maps & Geo",
        ),
        PatternRule(
            id="MAP-002",
            name="Google Maps Android API Key in Manifest",
            pattern=r"(?i)com\.google\.android\.(?:geo|maps)\.(?:v2\.)?API_KEY",
            file_patterns=["AndroidManifest.xml", "*.xml"],
            risk_level=RiskLevel.MEDIUM,
            description="Detected Google Maps API key declaration in AndroidManifest.",
            recommendation="Move the key to gradle.properties / local.properties and restrict it by package name and SHA-1.",
            category="Maps & Geo",
        ),
        PatternRule(
            id="MAP-003",
            name="2GIS / HERE / Mapy Key",
            pattern=(
                r"(?i)\b[a-z0-9_.\-]{0,40}(?:2gis|dgis|here[_\-]?maps|hereapi|mapy)[a-z0-9_.\-]{0,40}"
                r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"
            ),
            risk_level=RiskLevel.MEDIUM,
            description="Detected a third-party mapping provider API key.",
            recommendation="Restrict the key to your application and keep it out of the repository.",
            category="Maps & Geo",
        ),

        # ------------------------------------------------------------------
        # Analytics, attribution & push (mobile SDKs)
        # ------------------------------------------------------------------
        PatternRule(
            id="SDK-001",
            name="Sentry DSN",
            pattern=r"\bhttps://[a-f0-9]{32,64}@(?:o\d+\.ingest\.)?(?:[a-z0-9\-]+\.)*sentry\.io/\d+\b",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Sentry DSN containing a public client key.",
            recommendation="Client DSNs are semi-public, but rotate if it is a private/internal project.",
            category="Analytics & SDK",
        ),
        PatternRule(
            id="SDK-002",
            name="OneSignal API Key / App ID",
            pattern=(
                r"(?i)\b[a-z0-9_.\-]{0,30}onesignal[a-z0-9_.\-]{0,30}"
                r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,}|[0-9a-f\-]{36})[\"']"
            ),
            risk_level=RiskLevel.HIGH,
            description="Detected OneSignal REST API key or App ID.",
            recommendation="REST API keys must never ship in a client app. Rotate and move server-side.",
            category="Analytics & SDK",
        ),
        PatternRule(
            id="SDK-003",
            name="Amplitude / Mixpanel Token",
            pattern=(
                r"(?i)\b[a-z0-9_.\-]{0,30}(?:amplitude|mixpanel)[a-z0-9_.\-]{0,30}"
                r"[\"']?\s*[:=]\s*[\"']([a-f0-9]{32}|[A-Za-z0-9_\-]{20,})[\"']"
            ),
            risk_level=RiskLevel.MEDIUM,
            description="Detected Amplitude or Mixpanel project token.",
            recommendation="Use separate dev/prod tokens and load them from build configuration.",
            category="Analytics & SDK",
        ),
        PatternRule(
            id="SDK-004",
            name="AppsFlyer / Adjust / Branch Key",
            pattern=(
                r"(?i)\b[a-z0-9_.\-]{0,30}(?:appsflyer|adjust|branch)[a-z0-9_.\-]{0,30}"
                r"(?:dev)?[_\-]?(?:key|token|secret)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{12,})[\"']"
            ),
            risk_level=RiskLevel.MEDIUM,
            description="Detected mobile attribution SDK key (AppsFlyer / Adjust / Branch).",
            recommendation="Keep attribution dev keys out of the repository; inject at build time.",
            category="Analytics & SDK",
        ),
        PatternRule(
            id="SDK-005",
            name="AppMetrica / VK / Yandex SDK Key",
            pattern=(
                r"(?i)\b[a-z0-9_.\-]{0,30}(?:appmetrica|vkontakte|vk[_\-]?app|vk[_\-]?api)[a-z0-9_.\-]{0,30}"
                r"[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{8,})[\"']"
            ),
            risk_level=RiskLevel.MEDIUM,
            description="Detected AppMetrica or VK SDK application key.",
            recommendation="Load SDK keys from build configuration rather than hardcoding them.",
            category="Analytics & SDK",
        ),

        # ------------------------------------------------------------------
        # Messaging & communications
        # ------------------------------------------------------------------
        PatternRule(
            id="API-010",
            name="Slack API Token / Webhook",
            pattern=r"\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            risk_level=RiskLevel.HIGH,
            description="Detected Slack Bot Token or Incoming Webhook URL.",
            recommendation="Revoke token or webhook in Slack App Directory.",
            category="Messaging",
        ),
        PatternRule(
            id="API-011",
            name="Telegram Bot Token",
            pattern=r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Telegram Bot API Token.",
            recommendation="Revoke bot token via @BotFather on Telegram.",
            category="Messaging",
        ),
        PatternRule(
            id="API-012",
            name="Twilio Credentials",
            pattern=r"\bAC[a-f0-9]{32}\b|\bSK[a-f0-9]{32}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Twilio Account SID or API Key.",
            recommendation="Rotate credentials in Twilio Console.",
            category="Messaging",
        ),
        PatternRule(
            id="API-013",
            name="SendGrid API Key",
            pattern=r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected SendGrid Mail API Key.",
            recommendation="Revoke key in SendGrid dashboard.",
            category="Messaging",
        ),
        PatternRule(
            id="API-028",
            name="Discord Bot Token / Webhook",
            pattern=r"\b[MNO][a-zA-Z0-9_\-]{23,26}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27,40}\b|https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
            risk_level=RiskLevel.HIGH,
            description="Detected Discord bot token or webhook URL.",
            recommendation="Regenerate the bot token in the Discord Developer Portal.",
            category="Messaging",
        ),
        PatternRule(
            id="API-029",
            name="Firebase Cloud Messaging Server Key",
            pattern=r"\bAAAA[A-Za-z0-9_\-]{7,}:APA91b[A-Za-z0-9_\-]{100,}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Firebase Cloud Messaging legacy server key.",
            recommendation="FCM server keys must stay server-side. Rotate immediately if shipped in an app.",
            category="Messaging",
        ),

        # ------------------------------------------------------------------
        # Databases
        # ------------------------------------------------------------------
        PatternRule(
            id="DB-001",
            name="Database Connection URI",
            pattern=r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis[s]?|amqp[s]?|clickhouse|elasticsearch)://[^:\s]+:[^@\s]+@[^\s]+",
            risk_level=RiskLevel.CRITICAL,
            description="Detected hardcoded database connection URI with credentials.",
            recommendation="Remove embedded passwords from connection string; use environment variables.",
            category="Databases",
        ),
        PatternRule(
            id="DB-002",
            name="JDBC Connection String with Password",
            pattern=r"(?i)jdbc:[a-z0-9]+://[^\s\"']+[?&;]password=[^\s\"'&;]+",
            risk_level=RiskLevel.CRITICAL,
            description="Detected JDBC connection string containing an inline password.",
            recommendation="Move database credentials to environment variables or a secret manager.",
            category="Databases",
        ),

        # ------------------------------------------------------------------
        # Auth tokens
        # ------------------------------------------------------------------
        PatternRule(
            id="AUTH-001",
            name="JSON Web Token (JWT)",
            pattern=r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded JWT token.",
            recommendation="Do not hardcode JWT tokens in source code.",
            category="Auth",
        ),
        PatternRule(
            id="AUTH-002",
            name="Generic Bearer Token",
            pattern=r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.=]{20,})\b",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Authorization Bearer token header in code.",
            recommendation="Inject tokens dynamically at runtime.",
            category="Auth",
        ),
        PatternRule(
            id="AUTH-003",
            name="HTTP Basic Auth Header",
            pattern=r"(?i)\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded HTTP Basic authorization header (base64 user:password).",
            recommendation="Never hardcode Basic credentials; obtain them at runtime.",
            category="Auth",
        ),

        # ------------------------------------------------------------------
        # Cryptographic keys & PKI
        # ------------------------------------------------------------------
        PatternRule(
            id="KEY-001",
            name="Private Key Header",
            pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Private Encryption / Signing Key header.",
            recommendation="Remove private key file from repository; store in secure vault/keychain.",
            category="Crypto & PKI",
        ),
        PatternRule(
            id="KEY-002",
            name="Apple AuthKey p8 Private Key",
            pattern=r"-----BEGIN PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{50,}\s*-----END PRIVATE KEY-----",
            file_patterns=["*.p8", "Secrets.swift", "Config.swift"],
            risk_level=RiskLevel.CRITICAL,
            description="Detected Apple APNs or App Store Connect .p8 Private Key.",
            recommendation="Never commit .p8 keys. Keep in secure secrets management.",
            category="Crypto & PKI",
        ),
        PatternRule(
            id="KEY-003",
            name="PGP / OpenSSH Key Block",
            pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----|\bssh-rsa\s+AAAAB3NzaC1yc2E[A-Za-z0-9+/=]{100,}",
            risk_level=RiskLevel.HIGH,
            description="Detected PGP private key block or SSH key material.",
            recommendation="Remove key material from the repository and rotate the key pair.",
            category="Crypto & PKI",
        ),

        # ------------------------------------------------------------------
        # iOS / Swift / Xcode specifics
        # ------------------------------------------------------------------
        PatternRule(
            id="SWIFT-002",
            name="Swift Hardcoded Keychain / Cryptographic Secret",
            pattern=r"(?i)\b(?:kSecAttrGeneric|kSecValueData|cryptoKey|encryptionKey|hmacSecret|initializationVector|ivBytes)\s*=\s*[\"']([^\"']{4,})[\"']",
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded cryptographic or Keychain key literal in Swift source.",
            recommendation="Derive keys securely or load dynamically at runtime.",
            is_swift_rule=True,
            category="Mobile: iOS",
        ),
        PatternRule(
            id="IOS-001",
            name="Apple App Store Connect / Team Identifier",
            pattern=r"(?i)\b(?:ASC_|APP_STORE_CONNECT_|FASTLANE_)(?:API_)?(?:KEY_ID|ISSUER_ID|KEY|PASSWORD)\s*[:=]\s*[\"']?([A-Za-z0-9\-]{8,})[\"']?",
            risk_level=RiskLevel.HIGH,
            description="Detected App Store Connect API credential.",
            recommendation="Store App Store Connect credentials in CI secrets, never in the repository.",
            category="Mobile: iOS",
        ),
        PatternRule(
            id="IOS-002",
            name="Objective-C #define Secret",
            pattern=(
                r"^\s*#\s*define\s+[A-Za-z0-9_]{0,40}(?i:" + SECRET_WORDS + r")[A-Za-z0-9_]{0,40}\s+"
                r"@?[\"'](?!(?i:" + JUNK_VALUES + r")[\"'])(?![$<{@%])([^\s\"'()]{4,200})[\"']"
            ),
            risk_level=RiskLevel.HIGH,
            description="Detected a secret literal in an Objective-C preprocessor macro.",
            recommendation="Macros are compiled into the binary as plain strings. Move the value to a secure store.",
            category="Mobile: iOS",
        ),
        PatternRule(
            id="CONFIG-001",
            name="Fastlane / Match Credentials",
            pattern=r"(?i)\b(?:git_url|match_password|apple_id|app_identifier|FASTLANE_PASSWORD|FASTLANE_SESSION)\s*(?:\(\s*)?[\"']([^\"']+)[\"']",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Fastlane / Match credential in Fastfile or Appfile.",
            recommendation="Use environment variables in Fastlane configuration.",
            category="Mobile: iOS",
        ),

        # ------------------------------------------------------------------
        # Android / Kotlin / Gradle specifics
        # ------------------------------------------------------------------
        PatternRule(
            id="ANDROID-001",
            name="Android Signing Keystore Credential",
            pattern=(
                r"(?i)\b(?:store[_\-]?password|key[_\-]?password|store[_\-]?file|key[_\-]?alias|"
                r"signing[_\-]?(?:store|key)[_\-]?password)\s*[:=]\s*[\"']?([^\s\"'#]{3,})[\"']?"
            ),
            risk_level=RiskLevel.CRITICAL,
            description="Detected Android release signing keystore credential (storePassword / keyPassword / keyAlias).",
            recommendation="Move signing credentials to keystore.properties excluded from VCS, or to CI secrets.",
            category="Mobile: Android",
        ),
        PatternRule(
            id="ANDROID-002",
            name="Gradle Property Secret",
            pattern=(
                r"(?i)^\s*[a-z0-9_.]{0,40}(?:api[_\-]?key|secret|token|password|credential)[a-z0-9_.]{0,40}"
                r"\s*=\s*[\"']?(?![$<{@%])([^\s\"'#]{6,})"
            ),
            file_patterns=["gradle.properties", "local.properties", "keystore.properties", "*.properties"],
            risk_level=RiskLevel.HIGH,
            description="Detected a secret assigned in a Gradle/Java properties file.",
            recommendation="Keep local.properties and keystore.properties out of version control (.gitignore).",
            category="Mobile: Android",
        ),
        PatternRule(
            id="ANDROID-003",
            name="Android BuildConfig Hardcoded Secret",
            pattern=(
                r"(?i)buildConfigField\s*\(?\s*[\"']String[\"']\s*,\s*[\"'][a-z0-9_]*"
                r"(?:key|secret|token|password)[a-z0-9_]*[\"']\s*,\s*[\"'\\]{1,3}([^\s\"'\\]{6,})"
            ),
            risk_level=RiskLevel.HIGH,
            description="Detected a secret literal baked into an Android BuildConfig field.",
            recommendation="Read the value from a gitignored properties file or CI environment variable.",
            category="Mobile: Android",
        ),
        PatternRule(
            id="ANDROID-004",
            name="Android Resource String Secret",
            pattern=(
                r"(?i)<string\s+name\s*=\s*[\"'][a-z0-9_]*(?:api[_\-]?key|secret|token|password)[a-z0-9_]*[\"']\s*>"
                r"\s*(?![$<{@%])([^<\s]{8,})\s*</string>"
            ),
            file_patterns=["*.xml"],
            risk_level=RiskLevel.HIGH,
            description="Detected a secret stored in Android string resources (shipped in plain text inside the APK).",
            recommendation="String resources are trivially extractable from an APK. Move the secret server-side.",
            category="Mobile: Android",
        ),

        # ------------------------------------------------------------------
        # Configuration files & universal name-based detection
        # ------------------------------------------------------------------
        PatternRule(
            id="CONFIG-002",
            name="Hardcoded Secret in xcconfig",
            pattern=(
                r"(?i)^(?:[A-Z0-9_]*SECRET[A-Z0-9_]*|[A-Z0-9_]*TOKEN[A-Z0-9_]*|[A-Z0-9_]*KEY[A-Z0-9_]*)"
                r"\s*=\s*[\"']?(?![$<{@%])([^\s\"']{8,})"
            ),
            file_patterns=["*.xcconfig"],
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded secret parameter in Xcode xcconfig file.",
            recommendation="Exclude sensitive .xcconfig files from version control or pass via environment.",
            category="Config",
        ),
        PatternRule(
            id="CONFIG-003",
            name="Dotenv / Shell Environment Secret",
            pattern=(
                r"(?i)^\s*(?:export\s+)?[A-Z0-9_]{0,40}(?:API[_\-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]{0,40}"
                r"\s*=\s*[\"']?(?![$<{@%])([^\s\"'#]{6,})[\"']?"
            ),
            file_patterns=["*.env", ".env", "*.sh", "*.bash", "*.zsh", "*.cfg", "*.ini", "*.conf"],
            risk_level=RiskLevel.HIGH,
            description="Detected a secret assigned in an environment or shell configuration file.",
            recommendation="Keep .env files out of version control and load secrets at runtime.",
            category="Config",
        ),
        PatternRule(
            id="SWIFT-001",
            name="Sensitive Variable Assignment",
            pattern=build_name_assignment_pattern(SECRET_WORDS),
            risk_level=RiskLevel.HIGH,
            description=(
                "Detected an identifier whose name indicates a secret (api key, token, password, "
                "client secret, ...) assigned a hardcoded literal. Works across Swift, Kotlin, Java, "
                "Objective-C, JS/TS, Dart, Go, Python, JSON and YAML."
            ),
            recommendation="Move sensitive values into a secure store (Keychain / Keystore) or build-time configuration.",
            is_swift_rule=True,
            category="Config",
        ),
    ]

    return rules
