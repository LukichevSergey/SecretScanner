"""
Shannon entropy calculation module for detecting high-entropy random secrets.
"""

import math
import re
from typing import List, Tuple

# UUID pattern (e.g. 123e4567-e89b-12d3-a456-426614174000)
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Standard URL pattern
URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)

# Hex string pattern (e.g. commit hashes, SHA-256)
HEX_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32,64}$")

# Reverse domain / bundle id pattern (e.g., com.apple.dt.xcode)
BUNDLE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+$")


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    
    Formula: H(X) = - sum(P(x) * log2(P(x)))

    Args:
        data: Input string.

    Returns:
        Entropy float value between 0.0 and log2(alphabet_size).
    """
    if not data:
        return 0.0

    length = len(data)
    frequency: dict[str, int] = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return entropy


def is_false_positive_entropy(candidate: str) -> bool:
    """
    Determine if a candidate high-entropy string is a known false positive.
    
    Args:
        candidate: Extracted string literal or token.

    Returns:
        True if string is a false positive (UUID, URL, SHA hash, bundle ID, path).
    """
    clean = candidate.strip("\"'` \t\r\n")

    # Filter out empty or short strings
    if len(clean) < 20:
        return True

    # Filter out standard URLs
    if URL_PATTERN.match(clean):
        return True

    # Filter out standard UUIDs
    if UUID_PATTERN.match(clean):
        return True

    # Filter out standard hex hashes (e.g. SHA1/SHA256 commit hashes)
    if HEX_HASH_PATTERN.match(clean):
        return True

    # Filter out Bundle Identifiers
    if BUNDLE_ID_PATTERN.match(clean):
        return True

    # Filter out repeated pattern strings (e.g., "aaaaaaaaaaaaaaaaaaaaaa", "12345678901234567890")
    if len(set(clean)) <= 4:
        return True

    # Filter out typical path strings
    if clean.startswith("/") or clean.startswith("./") or clean.startswith("../"):
        return True

    # Filter out repetitive test strings or placeholders
    lower = clean.lower()
    placeholders = ["placeholder", "example", "sample", "your_secret", "dummy", "test"]
    if any(p in lower for p in placeholders):
        return True

    return False


def extract_high_entropy_candidates(
    line: str,
    min_length: int = 20,
    entropy_threshold: float = 4.5
) -> List[Tuple[str, float]]:
    """
    Extract string candidates from a line of code and return high-entropy matches.
    
    Args:
        line: Raw line of source code.
        min_length: Minimum string length to analyze (default 20).
        entropy_threshold: Shannon entropy cutoff value (default 4.5).

    Returns:
        List of tuples containing (matched_candidate_str, entropy_score).
    """
    results: List[Tuple[str, float]] = []

    # Extract quoted string literals (single, double, backtick, or Swift multi-line)
    quoted_tokens = re.findall(r'["\'`]([^\r\n"\'`]{' + str(min_length) + r',})["\'`]', line)
    
    # Also extract unquoted alphanumeric base64/hex token strings
    token_candidates = re.findall(r'[A-Za-z0-9+/=_\-]{' + str(min_length) + r',}', line)

    combined_candidates = set(quoted_tokens + token_candidates)

    for cand in combined_candidates:
        if len(cand) < min_length:
            continue

        if is_false_positive_entropy(cand):
            continue

        entropy = calculate_shannon_entropy(cand)
        if entropy >= entropy_threshold:
            results.append((cand, entropy))

    return results
