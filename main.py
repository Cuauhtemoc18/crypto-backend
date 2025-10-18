# main.py
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# Literal está en typing desde 3.8; si fallara, tomamos typing_extensions
try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal

# --- Crypto core (tu motor clásico) ---
from solve import crack_caesar, crack_vigenere

# --- ML (opcional) ---
try:
    from detector import detect_with_model  # devuelve (label, prob)
except Exception:
    detect_with_model = None

# --- Base de datos ---
from sqlalchemy.orm import Session
from sqlalchemy import func, select, cast
from sqlalchemy.sql.sqltypes import Date
from db import Base, engine, get_db
from models import DecryptLog
from crud import save_log

app = FastAPI(title="Crypto Analyzer AI", version="2.1 (English + DB)")

# CORS: permite que el frontend (Netlify) llame a este backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,              # déjalo en False salvo que uses cookies/sesiones
    allow_methods=["*"],
    allow_headers=["*"],
)

# CORS abierto para pruebas locales / front
# app.add_middleware(
 #   CORSMiddleware,
  #  allow_origins=["*"], allow_credentials=True,
   # allow_methods=["*"], allow_headers=["*"],
#)

# Crear tablas al iniciar (simple para esta entrega)
Base.metadata.create_all(bind=engine)


# --------- Modelos de request/response ----------
class DecryptReq(BaseModel):
    ciphertext: str
    algorithm: Literal["auto", "caesar", "vigenere"] = "auto"


class DecryptRes(BaseModel):
    detected: str
    plaintext: str
    key: Optional[str] = None
    score: Optional[float] = None
    klen: Optional[int] = None
    confidence: Optional[float] = None


# --------- Rutas ---------
@app.get("/")
def health():
    return {"status": "ok", "ml": detect_with_model is not None}


@app.post("/api/decrypt", response_model=DecryptRes)
def api_decrypt(req: DecryptReq, db: Session = Depends(get_db)):
    ct = req.ciphertext
    alg = req.algorithm
    if not ct or len(ct.strip()) == 0:
        raise HTTPException(400, "empty ciphertext")

    # Forzados
    if alg == "caesar":
        pt, meta = crack_caesar(ct)
        resp = DecryptRes(detected="caesar", plaintext=pt,
                          key=str(meta.get("key")), score=meta.get("score"))
        # Guardar log
        try:
            save_log(db, ciphertext=ct, detected=resp.detected, key=resp.key,
                     klen=None, score=resp.score, confidence=None, source="web")
        except Exception:
            pass
        return resp

    if alg == "vigenere":
        pt, meta = crack_vigenere(ct)
        resp = DecryptRes(detected="vigenere", plaintext=pt, key=meta.get("key"),
                          score=meta.get("score"), klen=meta.get("klen"))
        # Guardar log
        try:
            save_log(db, ciphertext=ct, detected=resp.detected, key=resp.key,
                     klen=resp.klen, score=resp.score, confidence=None, source="web")
        except Exception:
            pass
        return resp

    # ---- AUTO: gateway seguro con ML + baseline por score ----
    THRESH = float(os.getenv("ML_CONF_THRESH", "0.80"))   # umbral configurable
    USE_ML = True if detect_with_model is not None else False
    DELTA = float(os.getenv("ML_DELTA", "50"))            # margen de empate de scores

    # 1) Calcula ambos UNA sola vez (baseline por score)
    pt_c, meta_c = crack_caesar(ct)
    pt_v, meta_v = crack_vigenere(ct)

    sc_c = float(meta_c.get("score", -1e12))
    sc_v = float(meta_v.get("score", -1e12))
    diff = sc_v - sc_c  # >0 favorece Vigenère

    base_label = "caesar" if sc_c >= sc_v else "vigenere"
    base_pt, base_meta = (pt_c, meta_c) if base_label == "caesar" else (pt_v, meta_v)

    label, pt, meta, conf = base_label, base_pt, base_meta, None

    # 2) Si hay modelo, pedir predicción y aplicar gateway
    if USE_ML:
        try:
            ml_label, ml_conf = detect_with_model(ct)  # ("caesar"/"vigenere", 0..1)

            if ml_label == base_label:
                # Si están de acuerdo, seguimos baseline y reportamos confianza
                label, conf = ml_label, float(ml_conf)
                pt, meta = base_pt, base_meta
            elif (ml_conf is not None) and (ml_conf >= THRESH) and (abs(diff) < DELTA):
                # ML muy seguro y caso parejo por score → dejamos que mande ML
                label, conf = ml_label, float(ml_conf)
                pt, meta = (pt_c, meta_c) if label == "caesar" else (pt_v, meta_v)
            else:
                # Mantener baseline, reportando confianza del ML como referencia
                conf = float(ml_conf) if ml_conf is not None else None
        except Exception:
            # Si algo falla con el modelo, hacemos fallback al baseline silenciosamente
            pass

    resp = DecryptRes(
        detected=label,
        plaintext=pt,
        key=str(meta.get("key")) if meta else None,
        score=meta.get("score") if meta else None,
        klen=meta.get("klen") if meta else None,
        confidence=conf
    )

    # Guardar log en BD (sin plaintext, solo hash + métricas)
    try:
        save_log(
            db,
            ciphertext=req.ciphertext,
            detected=resp.detected,
            key=resp.key,
            klen=resp.klen,
            score=resp.score,
            confidence=resp.confidence,
            source="web"
        )
    except Exception:
        # No detener la respuesta si falla la BD
        pass

    return resp


# --------- Endpoints de estadísticas ---------
@app.get("/api/logs/last")
def api_logs_last(limit: int = 50, db: Session = Depends(get_db)):
    q = select(DecryptLog).order_by(DecryptLog.id.desc()).limit(min(limit, 200))
    rows = db.execute(q).scalars().all()
    return [
        {
            "id": r.id,
            "created_at": r.created_at,
            "detected": r.detected,
            "key": r.key_shown,
            "klen": r.klen,
            "score": r.score,
            "confidence": r.confidence,
            "ct_len": r.ct_len,
        } for r in rows
    ]


@app.get("/api/logs/stats")
def api_logs_stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(DecryptLog.id))) or 0
    by_algo = db.execute(
        select(DecryptLog.detected, func.count(DecryptLog.id)).group_by(DecryptLog.detected)
    ).all()
    avg_conf = db.scalar(select(func.avg(DecryptLog.confidence))) or 0
    avg_len = db.scalar(select(func.avg(DecryptLog.ct_len))) or 0
    return {
        "total": int(total),
        "by_algo": dict(by_algo),
        "avg_confidence": float(avg_conf or 0),
        "avg_ct_len": float(avg_len or 0),
    }


@app.get("/api/logs/stats_by_day")
def api_logs_stats_by_day(db: Session = Depends(get_db)):
    rows = db.execute(
        select(cast(DecryptLog.created_at, Date), func.count(DecryptLog.id))
        .group_by(cast(DecryptLog.created_at, Date))
        .order_by(cast(DecryptLog.created_at, Date).desc())
    ).all()
    return [{"date": str(d), "count": int(n)} for d, n in rows]
