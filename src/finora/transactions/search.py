"""Búsqueda sin distinguir mayúsculas ni tildes (FEAT-TRX, RF-TRX-05, SUP-TRX-04).

Se normaliza en Python, al guardar (`search_text`) y al buscar, para no depender de la
extensión `unaccent` de PostgreSQL (plan.md §14).
"""

import unicodedata


def normalize(text: str) -> str:
    """Minúsculas, sin tildes ni diacríticos y con los espacios colapsados.

    "Café ÁRBOL" → "cafe arbol"; "Año" → "ano" (la ñ también pierde su tilde, así que
    "ano" encuentra "año").
    """
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return " ".join(stripped.split())


def search_text(description: str | None, note: str | None) -> str:
    """Valor de la columna `search_text`: descripción y nota normalizadas."""
    return "\n".join(normalize(t) for t in (description, note) if t)


def like_pattern(query: str) -> str:
    """Patrón `LIKE` que busca `query` normalizado como texto literal.

    Escapa `\\`, `%` y `_` para que el usuario no pueda usarlos como comodines; la
    consulta debe usar `ESCAPE '\\'` (el valor por defecto en PostgreSQL).
    """
    escaped = normalize(query).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
