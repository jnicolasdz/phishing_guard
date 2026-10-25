from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from email.message import Message
from hashlib import sha256
from datetime import datetime, timezone
from urllib.parse import urlsplit
import re

URL_RE = re.compile(r'''https?://[^\s<>"\'()]+''', re.I)
INVISIBLE_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u00ad]")

class _HTMLText(HTMLParser):
    SKIP = {"script", "style", "head"}
    BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3"}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip, self.links = [], 0, []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in self.SKIP: self.skip += 1
        if tag in self.BLOCK: self.parts.append("\n")
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
    def handle_endtag(self, tag):
        if tag in self.SKIP: self.skip = max(0, self.skip - 1)
        if tag in self.BLOCK: self.parts.append("\n")
    def handle_data(self, data):
        if not self.skip: self.parts.append(data)

def clean_text(value: str) -> str:
    value = INVISIBLE_RE.sub("", value or "").replace("\xa0", " ")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r" ?\n ?", "\n", value)
    return re.sub(r"\n{3,}", "\n\n", value).strip()

def _decode_part(part: Message) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except (LookupError, UnicodeError, TypeError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")

def normalize_email(raw: bytes, source: dict, max_body_chars: int = 12000) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    plain, html, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename or "unnamed",
                "content_type": ctype,
                "size": len(payload),
                "sha256": sha256(payload).hexdigest() if payload else None,
            })
            continue
        if ctype == "text/plain":
            plain.append(_decode_part(part))
        elif ctype == "text/html":
            html.append(_decode_part(part))

    html_parser = _HTMLText()
    html_text = ""
    if html:
        try:
            html_parser.feed("\n".join(html))
            html_text = clean_text("".join(html_parser.parts))
        except Exception:
            html_text = ""
    body_text = clean_text("\n".join(plain)) or html_text
    body_text = body_text[:max_body_chars]
    urls = list(dict.fromkeys(URL_RE.findall("\n".join([body_text] + html))))
    date = msg.get("Date")
    try:
        parsed_date = date.datetime.isoformat() if date and date.datetime else None
    except Exception:
        parsed_date = None
    raw_hash = sha256(raw).hexdigest()
    return {
        "source": source,
        "message_id_header": str(msg.get("Message-ID", "")) or None,
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "cc": str(msg.get("Cc", "")),
        "subject": str(msg.get("Subject", "")),
        "date": parsed_date,
        "headers": {
            "reply_to": str(msg.get("Reply-To", "")),
            "return_path": str(msg.get("Return-Path", "")),
            "authentication_results": str(msg.get("Authentication-Results", "")),
        },
        "body_text": body_text,
        "urls": urls,
        "attachments": attachments,
        "content_sha256": raw_hash,
        "acquired_at": datetime.now(timezone.utc).isoformat(),
    }
