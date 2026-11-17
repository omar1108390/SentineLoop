"""Layer 0: decode common encodings and normalize invisible characters."""

import base64
import codecs
import re
import unicodedata
from html import unescape
from urllib.parse import unquote

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalize(text: str) -> str:
    value = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)
    value = unescape(unquote(value))
    # Include HTML comments and tags' text in inspection; remove markup afterwards.
    value = re.sub(r"<!--(.*?)-->", r" \1 ", value, flags=re.DOTALL)
    value = re.sub(r"<[^>]*>", " ", value)
    candidates = [value]
    for token in re.findall(r"(?<!\w)[A-Za-z0-9+/]{16,}={0,2}(?!\w)", value):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
            if decoded.isprintable() and len(decoded) <= 4000:
                candidates.append(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    candidates.append(codecs.encode(value, "rot_13"))
    # Keep both original and decoded representations so decoding never hides source context.
    return "\n".join(candidates).casefold()
