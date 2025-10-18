from sqlalchemy import Integer, String, Float, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from db import Base

class DecryptLog(Base):
    __tablename__ = "decrypt_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now())

    ct_hash: Mapped[str] = mapped_column(String(64), index=True)   # sha256 hex
    ct_len:  Mapped[int] = mapped_column(Integer)

    detected: Mapped[str] = mapped_column(String(16))              # "caesar"/"vigenere"
    key_shown: Mapped[str] = mapped_column(String(128), nullable=True)
    klen: Mapped[int] = mapped_column(Integer, nullable=True)

    score: Mapped[float] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=True)

    source: Mapped[str] = mapped_column(String(64), nullable=True)
