# crud.py
import hashlib
from typing import Optional
from sqlalchemy.orm import Session
from models import DecryptLog

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def save_log(
    db: Session,
    *,
    ciphertext: str,
    detected: str,
    key: Optional[str] = None,
    klen: Optional[int] = None,
    score: Optional[float] = None,
    confidence: Optional[float] = None,
    source: Optional[str] = None
) -> DecryptLog:
    log = DecryptLog(
        ct_hash = sha256_hex(ciphertext),
        ct_len  = len("".join(ch for ch in ciphertext if ch.isalpha())),
        detected= detected,
        key_shown = key if key else None,
        klen = klen,
        score = float(score) if score is not None else None,
        confidence = float(confidence) if confidence is not None else None,
        source = source
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log
