"""Short complete-text pilot extraction. No OCR or silent document truncation."""
from email import policy
from email.parser import BytesParser
from io import BytesIO


def extract(data: bytes, format: str, *, max_bytes=8192):
    meta = {"format": format, "parts": 0, "complete": False, "ocr_supported": False}
    try:
        if len(data) > 2_000_000: raise ValueError("source too large for pilot")
        if format == "text":
            text, meta["parts"] = data.decode("utf-8"), 1
        elif format == "email":
            message = BytesParser(policy=policy.default).parsebytes(data)
            parts = []
            for part in message.walk():
                if part.is_multipart(): continue
                if part.get_content_type() != "text/plain" or part.get_content_disposition() == "attachment":
                    raise ValueError("HTML/non-text attachment requires separate extraction")
                parts.append(part.get_content())
            if message.defects or not parts: raise ValueError("email extraction incomplete")
            headers = "\n".join(f"{key}: {value}" for key, value in message.items())
            text, meta["parts"] = headers + "\n\n" + "\n".join(parts), len(parts)
        elif format == "pdf":
            from pypdf import PdfReader
            pdf = PdfReader(BytesIO(data), strict=True)
            if pdf.is_encrypted or len(pdf.pages) > 8: raise ValueError("encrypted/large PDF outside pilot")
            pages = [p.extract_text() for p in pdf.pages]
            if not pages or any(not p or not p.strip() for p in pages): raise ValueError("empty/image PDF; OCR unsupported")
            text, meta["parts"] = "\n".join(pages), len(pages)
        else: raise ValueError("unsupported extraction format")
        size = len(text.encode("utf-8"))
        meta.update(extracted_bytes=size, covered_bytes=size, source_bytes=len(data))
        if not text.strip() or size > max_bytes: raise ValueError("empty/too long; no whole-document inference")
        meta["complete"] = True
        return {"status": "EXTRACTED", "text": text, "metadata": meta}
    except Exception as exc:
        meta["reason"] = type(exc).__name__
        return {"status": "UNKNOWN", "text": None, "metadata": meta}
