"""
Utility functions for file handling, secret redaction, and string processing.
"""

from pathlib import Path
from typing import List, Tuple
from secret_scanner.models import MatchContext


def redact_secret(matched: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive secrets while keeping a short prefix and suffix visible for debugging.
    
    Args:
        matched: The raw matched secret string.
        visible_chars: Number of characters to keep visible at start/end.

    Returns:
        Redacted string preview (e.g. "sk-1...a89f").
    """
    clean_str = matched.strip("'\" \t\r\n")
    if len(clean_str) <= visible_chars * 2:
        return "*" * len(clean_str)

    prefix = clean_str[:visible_chars]
    suffix = clean_str[-visible_chars:]
    masked_len = max(4, len(clean_str) - (visible_chars * 2))
    return f"{prefix}{'*' * min(masked_len, 12)}..{suffix}"


def is_binary_file(file_path: Path, sample_size: int = 4096) -> bool:
    """
    Check if a file appears to be binary by inspecting sample bytes.
    
    Args:
        file_path: Absolute or relative Path to file.
        sample_size: Bytes to read for binary check.

    Returns:
        True if binary characters (NULL bytes) are detected.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            if b"\x00" in chunk:
                return True
            # High proportion of non-ASCII bytes indicates binary
            text_characters = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
            non_text = chunk.translate(None, text_characters)
            return len(non_text) / max(len(chunk), 1) > 0.3
    except Exception:
        return True


def extract_context(lines: List[str], line_idx: int, context_size: int = 20) -> MatchContext:
    """
    Extract up to `context_size` lines before and after a specified 0-indexed line index.
    
    Args:
        lines: Full list of lines in the file.
        line_idx: 0-based index of the matching line.
        context_size: Number of lines to extract before/after (default 20).

    Returns:
        MatchContext object with 1-based line number and sliced lists.
    """
    start_before = max(0, line_idx - context_size)
    lines_before = [lines[i].rstrip("\r\n") for i in range(start_before, line_idx)]
    
    current_line = lines[line_idx].rstrip("\r\n") if 0 <= line_idx < len(lines) else ""
    
    end_after = min(len(lines), line_idx + 1 + context_size)
    lines_after = [lines[i].rstrip("\r\n") for i in range(line_idx + 1, end_after)]

    return MatchContext(
        lines_before=lines_before,
        line_content=current_line,
        line_number=line_idx + 1,  # 1-indexed for display
        lines_after=lines_after,
    )


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 1.0:
        return f"{seconds * 1000:.1f} ms"
    elif seconds < 60.0:
        return f"{seconds:.2f} s"
    else:
        mins = int(seconds // 60)
        secs = seconds % 60
        return f"{mins}m {secs:.1f}s"
