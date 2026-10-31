"""Validaciones de texto compartidas por todas las features."""

import unicodedata


def strip_control_characters(value: str) -> str:
    """Quita saltos de línea y demás caracteres de control (categoría Unicode Cc)."""
    return "".join(c for c in value if unicodedata.category(c) != "Cc")


def reject_control_characters(value: str) -> str:
    """Validador de Pydantic: texto de una línea, sin caracteres de control.

    Los nombres aparecen en correos y pantallas: un salto de línea permitiría armar
    texto engañoso (T-AUTH-QA-03).
    """
    if strip_control_characters(value) != value:
        raise ValueError("El texto no puede tener saltos de línea ni caracteres de control.")
    return value
