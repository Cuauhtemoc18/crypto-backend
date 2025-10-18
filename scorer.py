# scorer.py
import json, unicodedata
from pathlib import Path

def only_letters(s: str) -> str:
    nfkd = unicodedata.normalize("NFD", s)
    s = "".join(c for c in nfkd if unicodedata.category(c) != "Mn")
    return "".join(ch for ch in s.upper() if 'A' <= ch <= 'Z')

class NGramScorer:
    """
    Mezcla lineal con backoff: 4-gramas, 3-gramas, 2-gramas y 1-gramas.
    Pesos ajustables. Devuelve suma de log-probabilidades (más alto = mejor inglés).
    """
    def __init__(self,
                 mono_path="monograms_en.json",
                 bi_path="bigrams_en.json",
                 tri_path="trigrams_en.json",
                 quad_path="quadgrams_en.json",
                 weights=(0.65, 0.22, 0.09, 0.04)):  # (quad, tri, bi, mono)
        self.mono = json.loads(Path(mono_path).read_text(encoding="utf-8"))
        self.bi   = json.loads(Path(bi_path).read_text(encoding="utf-8"))
        self.tri  = json.loads(Path(tri_path).read_text(encoding="utf-8"))
        self.quad = json.loads(Path(quad_path).read_text(encoding="utf-8"))

        self.q = self.quad["logp"]; self.q_fb = float(self.quad["fallback"])
        self.t = self.tri["logp"];  self.t_fb = float(self.tri["fallback"])
        self.b = self.bi["logp"];   self.b_fb = float(self.bi["fallback"])
        self.m = self.mono["logp"]; self.m_fb = float(self.mono["fallback"])

        self.w_quad, self.w_tri, self.w_bi, self.w_mono = weights

        # distrib monográfica (para chi-cuadrado de Vigenère)
        # a partir de logp -> probas lineales normalizadas
        import math
        probs = {k: 10**v for k, v in self.m.items()}
        Z = sum(probs.values()) or 1.0
        self.mono_freq = {k: (probs[k]/Z)*100.0 for k in probs}  # en %

    def score(self, text: str) -> float:
        s = only_letters(text)
        n = len(s)
        if n == 0:
            return -1e12
        score = 0.0

        # 4-gramas
        if n >= 4 and self.w_quad > 0:
            for i in range(n-3):
                g = s[i:i+4]
                score += self.w_quad * (self.q.get(g, self.q_fb))
        # 3-gramas
        if n >= 3 and self.w_tri > 0:
            for i in range(n-2):
                g = s[i:i+3]
                score += self.w_tri * (self.t.get(g, self.t_fb))
        # 2-gramas
        if n >= 2 and self.w_bi > 0:
            for i in range(n-1):
                g = s[i:i+2]
                score += self.w_bi * (self.b.get(g, self.b_fb))
        # 1-gramas
        if self.w_mono > 0:
            for i in range(n):
                g = s[i]
                score += self.w_mono * (self.m.get(g, self.m_fb))

        return score
