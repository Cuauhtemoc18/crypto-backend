# features.py
import math
from collections import Counter
from solve import only_letters, crack_caesar, crack_vigenere

def index_of_coincidence(s: str) -> float:
    n = len(s)
    if n <= 1: return 0.0
    c = Counter(s)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

def entropy(s: str) -> float:
    n = len(s)
    if n == 0: return 0.0
    c = Counter(s)
    return -sum((v/n)*math.log((v/n)+1e-12) for v in c.values())

def extract_features(ct: str):
    s = only_letters(ct)
    n = len(s)

    # Reusa tu motor actual (no cambia tu lógica):
    _, meta_c = crack_caesar(ct)
    _, meta_v = crack_vigenere(ct)

    s_c = float(meta_c.get("score", 0.0))
    s_v = float(meta_v.get("score", 0.0))

    return [
        n,                          # longitud útil
        index_of_coincidence(s),    # IC
        entropy(s),                 # entropía
        s_c,                        # score si fuera César
        s_v,                        # score si fuera Vigenère
        s_v - s_c,                  # diferencia de scores
    ]
