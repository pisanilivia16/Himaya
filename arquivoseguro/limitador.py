import threading
import time
from collections import defaultdict


class LimitadorTentativas:
    """Janela deslizante em memória. Registra falhas por chave (IP ou e-mail)."""

    def __init__(self, limite: int, janela: int):
        self.limite = limite
        self.janela = janela
        self._falhas: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _limpar(self, chave: str) -> list[float]:
        agora = time.time()
        recentes = [t for t in self._falhas[chave] if agora - t < self.janela]
        if recentes:
            self._falhas[chave] = recentes
        else:
            self._falhas.pop(chave, None)
        return recentes

    def bloqueado(self, chave: str) -> bool:
        with self._lock:
            return len(self._limpar(chave)) >= self.limite

    def registrar_falha(self, chave: str) -> None:
        with self._lock:
            self._limpar(chave)
            self._falhas[chave].append(time.time())

    def limpar(self, chave: str) -> None:
        with self._lock:
            self._falhas.pop(chave, None)
