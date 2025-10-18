# solve.py (English, robust)
import unicodedata
from typing import Tuple, Dict, List
from collections import Counter
from scorer import NGramScorer

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
SCORER = NGramScorer()

# ---------- utils
def minimal_period(s: str) -> str:
    if not s:
        return s
    n = len(s)
    for p in range(1, n+1):
        if n % p == 0 and s == s[:p] * (n // p):
            return s[:p]
    return s

def strip_accents(s: str) -> str:
    nfkd = unicodedata.normalize('NFD', s)
    return "".join(c for c in nfkd if unicodedata.category(c) != 'Mn')

def only_letters(s: str) -> str:
    s = strip_accents(s)
    return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

def score_text(s: str) -> float:
    return SCORER.score(s)

# ---------- Caesar
def _shift_char(ch: str, k: int) -> str:
    if 'A' <= ch <= 'Z': return chr((ord(ch)-65+k)%26 + 65)
    if 'a' <= ch <= 'z': return chr((ord(ch)-97+k)%26 + 97)
    return ch

def caesar_decrypt(text: str, k: int) -> str:
    return "".join(_shift_char(ch, -k) for ch in text)

def crack_caesar(ct: str) -> Tuple[str, Dict]:
    best, best_k, best_s = None, 0, -1e12
    for k in range(26):
        pt = caesar_decrypt(ct, k)
        s = score_text(pt)
        if s > best_s:
            best, best_k, best_s = pt, k, s
    return best, {"key": best_k, "score": best_s}

# ---------- Vigenère

# Usaremos las frecuencias monográficas obtenidas del corpus (más realistas que las fijas)
MONO_FREQ = SCORER.mono_freq  # dict 'A'..'Z' -> porcentaje

def chi_squared_for_shift(column: str, shift: int) -> float:
    counts = [0]*26; total = 0
    for ch in column:
        if 'A' <= ch <= 'Z':
            idx = (ord(ch)-65 - shift) % 26
            counts[idx]+=1; total+=1
    if total == 0:
        return 1e12
    chi = 0.0
    for i in range(26):
        expected = MONO_FREQ[ALPHA[i]]/100.0 * total
        diff = counts[i]-expected
        chi += (diff*diff)/(expected+1e-12)
    return chi

def estimate_key_len_candidates(ct: str, max_k: int = 18, top: int = 4) -> List[int]:
    s = only_letters(ct)
    if len(s) < 24:
        return [2,3,4]

    def ic(sub: str) -> float:
        c = Counter(sub); n = len(sub)
        return sum(f*(f-1) for f in c.values())/(n*(n-1)+1e-12)

    scores=[]
    for k in range(1, min(max_k, max(2, len(s)//2))+1):
        ics=[]
        for i in range(k):
            col = s[i::k]
            ics.append(ic(col) if len(col)>1 else 0.0)
        scores.append((sum(ics)/len(ics), k))
    scores.sort(reverse=True)
    return [k for _,k in scores[:top]]

def vigenere_decrypt_with_key(ct: str, key: str) -> str:
    res=[]; j=0
    for ch in ct:
        if ch.isalpha():
            k = (ord(key[j%len(key)].upper())-65)
            base = 65 if ch.isupper() else 97
            res.append(chr((ord(ch)-base - k)%26 + base)); j+=1
        else:
            res.append(ch)
    return "".join(res)

def crack_vigenere(ct: str,
                   beam_width: int = 10,
                   top_shifts_per_col: int = 4) -> Tuple[str, Dict]:
    letters = only_letters(ct)
    if len(letters) < 10:
        return ct, {"key":"?", "score":-1e12, "klen":1}

    best_overall = ("", -1e12, "")
    for klen in estimate_key_len_candidates(ct):
        # Para cada columna, tomamos los shifts con menor chi2 (monogramas)
        col_shifts=[]
        for i in range(klen):
            col = letters[i::klen]
            ranked = sorted([(chi_squared_for_shift(col,s), s) for s in range(26)])[:top_shifts_per_col]
            col_shifts.append([s for _,s in ranked])

        # Beam search sobre el espacio de claves
        beams = [("", -1e12)]  # (key_prefix, score) score real solo cuando completamos la clave
        for pos in range(klen):
            new_beams=[]
            for key_pref, _ in beams:
                for s in col_shifts[pos]:
                    cand_key = key_pref + chr(65+s)
                    if len(cand_key)==klen:
                        pt = vigenere_decrypt_with_key(ct, cand_key)
                        sc = score_text(pt)
                        new_beams.append((cand_key, sc))
                    else:
                        new_beams.append((cand_key, -1e12))
            new_beams.sort(key=lambda x: x[1], reverse=True)
            beams = new_beams[:max(beam_width, 10)]

        if beams:
            beams.sort(key=lambda x: x[1], reverse=True)
            cand_key, sc = beams[0]
            pt = vigenere_decrypt_with_key(ct, cand_key)
            if sc > best_overall[1]:
                best_overall = (pt, sc, cand_key)

    pt, sc, key = best_overall

    # --- NUEVO: normaliza la clave a su período mínimo ---
    key_norm = minimal_period(key) if key else key

    # (Opcional pero recomendado) si encogió, recalcula el plaintext con la clave compacta.
    # El texto descifrado será el mismo, pero dejamos todo coherente.
    if key_norm and key_norm != key:
        pt = vigenere_decrypt_with_key(ct, key_norm)

    return pt, {"key": key_norm, "score": sc, "klen": len(key_norm) if key_norm else None}


# ---------- AUTO
def detect_algorithm(ct: str) -> str:
    pt_c, meta_c = crack_caesar(ct)
    pt_v, meta_v = crack_vigenere(ct)
    return "caesar" if meta_c["score"] >= meta_v["score"] else "vigenere"

def decrypt_auto(ct: str) -> Tuple[str, Dict]:
    alg = detect_algorithm(ct)
    if alg=="caesar":
        pt, meta = crack_caesar(ct)
    else:
        pt, meta = crack_vigenere(ct)
    meta["detected"]=alg
    return pt, meta
