"""
Regex pattern rules engine for SecretScanner.
Includes Gitleaks, TruffleHog, and iOS/Swift/Xcode specific security audit rules.
"""

from typing import List
from secret_scanner.models import PatternRule, RiskLevel


def get_all_rules() -> List[PatternRule]:
    """Return the complete list of built-in pattern detection rules."""

    rules: List[PatternRule] = [
        # --- API & Cloud Service Keys ---
        PatternRule(
            id="API-001",
            name="OpenAI API Key",
            pattern=r"\bsk-(?:proj-|admin-)?[a-zA-Z0-9_-]{32,64}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected OpenAI API key or Project secret key.",
            recommendation="Revoke the API key in OpenAI Dashboard and move it to environment variables or Keychain."
        ),
        PatternRule(
            id="API-002",
            name="Anthropic API Key",
            pattern=r"\bsk-ant-api03-[a-zA-Z0-9_-]{80,100}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Anthropic Claude API key.",
            recommendation="Revoke key in Anthropic Console immediately."
        ),
        PatternRule(
            id="API-003",
            name="Google API Key",
            pattern=r"\bAIza[0-9A-Za-z-_]{35}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Google Cloud / Firebase API key.",
            recommendation="Restrict API key permissions in Google Cloud Console or store in secure Keychain."
        ),
        PatternRule(
            id="API-004",
            name="AWS Access Key ID",
            pattern=r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected AWS Access Key ID.",
            recommendation="Check IAM policies, rotate key pair, and store in AWS Secrets Manager."
        ),
        PatternRule(
            id="API-005",
            name="AWS Secret Access Key",
            pattern=r"(?i)\baws_?(?:secret)?_?(?:access)?_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            risk_level=RiskLevel.CRITICAL,
            description="Detected AWS Secret Access Key.",
            recommendation="Immediately rotate AWS IAM credentials."
        ),
        PatternRule(
            id="API-006",
            name="GitHub Personal Access Token",
            pattern=r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected GitHub Personal Access Token.",
            recommendation="Revoke token in GitHub Settings > Developer settings > Access tokens."
        ),
        PatternRule(
            id="API-007",
            name="GitLab Personal Access Token",
            pattern=r"\bglpat-[a-zA-Z0-9\-]{20,30}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected GitLab Personal Access Token.",
            recommendation="Revoke token in GitLab User Settings > Access Tokens."
        ),
        PatternRule(
            id="API-008",
            name="Stripe Secret Key",
            pattern=r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Stripe API Secret Key.",
            recommendation="Roll key in Stripe Developer Dashboard."
        ),
        PatternRule(
            id="API-009",
            name="RevenueCat API Key",
            pattern=r"\b(?:appl|goog)_[a-zA-Z0-9]{32,64}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected RevenueCat API Key.",
            recommendation="Verify RevenueCat key scope and do not expose secret key in client app binary."
        ),
        PatternRule(
            id="API-010",
            name="Slack API Token / Webhook",
            pattern=r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            risk_level=RiskLevel.HIGH,
            description="Detected Slack Bot Token or Incoming Webhook URL.",
            recommendation="Revoke token or webhook in Slack App Directory."
        ),
        PatternRule(
            id="API-011",
            name="Telegram Bot Token",
            pattern=r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Telegram Bot API Token.",
            recommendation="Revoke bot token via @BotFather on Telegram."
        ),
        PatternRule(
            id="API-012",
            name="Twilio Credentials",
            pattern=r"\bAC[a-f0-9]{32}\b|\bSK[a-f0-9]{32}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected Twilio Account SID or API Key.",
            recommendation="Rotate credentials in Twilio Console."
        ),
        PatternRule(
            id="API-013",
            name="SendGrid API Key",
            pattern=r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected SendGrid Mail API Key.",
            recommendation="Revoke key in SendGrid dashboard."
        ),
        PatternRule(
            id="API-014",
            name="Mapbox Access Token",
            pattern=r"\b[ps]k\.eyJ1I[a-zA-Z0-9._-]{50,150}\b",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Mapbox Public or Secret Token.",
            recommendation="Restrict token scopes or move secret tokens out of client code."
        ),
        PatternRule(
            id="API-015",
            name="Supabase Service Key",
            pattern=r"\bsbp_[a-f0-9]{40}\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Supabase Service Role Key.",
            recommendation="Service role keys bypass RLS. Move to secure backend server."
        ),

        # --- Connection Strings & Databases ---
        PatternRule(
            id="DB-001",
            name="Database Connection URI",
            pattern=r"\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis[s]?|amqp[s]?|elasticsearch)://[^:\s]+:[^@\s]+@[^\s]+\b",
            risk_level=RiskLevel.CRITICAL,
            description="Detected hardcoded database connection URI with credentials.",
            recommendation="Remove embedded passwords from connection string; use environment variables."
        ),

        # --- JWT & Authentication Tokens ---
        PatternRule(
            id="AUTH-001",
            name="JSON Web Token (JWT)",
            pattern=r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded JWT token.",
            recommendation="Do not hardcode JWT tokens in source code."
        ),
        PatternRule(
            id="AUTH-002",
            name="Generic Bearer Token",
            pattern=r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.=]{20,})\b",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Authorization Bearer token header in code.",
            recommendation="Inject tokens dynamically at runtime."
        ),

        # --- Cryptographic Keys & PKI ---
        PatternRule(
            id="KEY-001",
            name="Private Key Header",
            pattern=r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)? PRIVATE KEY-----",
            risk_level=RiskLevel.CRITICAL,
            description="Detected Private Encryption / Signing Key header.",
            recommendation="Remove private key file from repository; store in secure vault/keychain."
        ),
        PatternRule(
            id="KEY-002",
            name="Apple AuthKey p8 Private Key",
            pattern=r"-----BEGIN PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{50,}\s*-----END PRIVATE KEY-----",
            file_patterns=["*.p8", "Secrets.swift", "Config.swift"],
            risk_level=RiskLevel.CRITICAL,
            description="Detected Apple APNs or App Store Connect .p8 Private Key.",
            recommendation="Never commit .p8 keys. Keep in secure secrets management."
        ),

        # --- Swift & Xcode Specific Assignment Patterns ---
        PatternRule(
            id="SWIFT-001",
            name="Swift Sensitive Variable Assignment",
            pattern=r"(?i)\b(?:let|var)\s+(?:password|passwd|secret|clientSecret|privateKey|refreshToken|accessToken|authorization|bearer|apikey|api_key|secret_key|authToken|cookie|session|credential)\s*(?::\s*String)?\s*=\s*[\"']([^\"']{4,})[\"']",
            risk_level=RiskLevel.HIGH,
            description="Detected sensitive keyword variable with hardcoded String literal in Swift code.",
            recommendation="Move sensitive parameters to secure Keychain (SecItem) or fetch from secure endpoint.",
            is_swift_rule=True
        ),
        PatternRule(
            id="SWIFT-002",
            name="Swift Hardcoded Keychain / Cryptographic Secret",
            pattern=r"(?i)\b(?:kSecAttrGeneric|kSecValueData|cryptoKey|encryptionKey|hmacSecret)\s*=\s*[\"']([^\"']{4,})[\"']",
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded cryptographic or Keychain key literal in Swift source.",
            recommendation="Derive keys securely or load dynamically at runtime.",
            is_swift_rule=True
        ),

        # --- CI/CD & Configuration Files ---
        PatternRule(
            id="CONFIG-001",
            name="Fastlane / Match Credentials",
            pattern=r"(?i)\b(?:git_url|match_password|apple_id|app_identifier)\s*\(\s*[\"']([^\"']+)[\"']\s*\)",
            risk_level=RiskLevel.MEDIUM,
            description="Detected Fastlane / Match credential in Fastfile or Appfile.",
            recommendation="Use environment variables in Fastlane configuration."
        ),
        PatternRule(
            id="CONFIG-002",
            name="Hardcoded Secret in xcconfig",
            pattern=r"(?i)^(?:[A-Z0-9_]*SECRET[A-Z0-9_]*|[A-Z0-9_]*TOKEN[A-Z0-9_]*|[A-Z0-9_]*KEY[A-Z0-9_]*)\s*=\s*([^\s]{8,})",
            risk_level=RiskLevel.HIGH,
            description="Detected hardcoded secret parameter in Xcode xcconfig file.",
            recommendation="Exclude sensitive .xcconfig files from version control or pass via environment."
        ),
    ]

    return rules
