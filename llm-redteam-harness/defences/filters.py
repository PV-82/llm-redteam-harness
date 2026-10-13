import html
import re

from app.config import MAX_INPUT_CHARS, MAX_OUTPUT_CHARS, SECRET, SYSTEM_MARKER

DENY = re.compile(
    r"ignore (all |any )?(previous|prior|above|your)|disregard|you are now|developer mode|"
    r"system prompt|api[\s_-]?key|password|credential", re.I)
EXT_IMG = re.compile(r"!\[[^\]]*\]\(https?://[^)]*\)")
ALLOWED_TOOLS = {"lookup_order"}


def input_check(text):
    """Return a block reason, or None if the input passes."""
    if len(text) > MAX_INPUT_CHARS:
        return "input too long"
    if DENY.search(text):
        return "deny-list match"
    return None


def output_sanitise(text):
    text = text.replace(SECRET, "[REDACTED]").replace(SYSTEM_MARKER, "[REDACTED]")
    text = EXT_IMG.sub("[image removed]", text)
    return html.escape(text, quote=False)


def output_cap(text):
    return text if len(text) <= MAX_OUTPUT_CHARS else text[:MAX_OUTPUT_CHARS] + " ...[truncated]"


def tool_allowed(name):
    return name in ALLOWED_TOOLS


def doc_allowed(doc):
    return doc.source == "trusted" and doc.access == "public"
