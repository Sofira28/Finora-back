"""Catálogo de categorías y búsqueda normalizada (T-TRX-BE-01, RN-TRX-07, SUP-TRX-04)."""

import pytest

from finora.transactions.categories import LABELS, categories_for, is_allowed, matching
from finora.transactions.models import Category, TransactionType
from finora.transactions.search import like_pattern, normalize, search_text

EXPENSE, INCOME = TransactionType.EXPENSE, TransactionType.INCOME
TRANSFER, ADJUSTMENT = TransactionType.TRANSFER, TransactionType.ADJUSTMENT

# --- Catálogo ------------------------------------------------------------------------------


def test_todas_las_categorias_tienen_nombre() -> None:
    assert set(LABELS) == set(Category)
    assert len(Category) == 13


def test_categorias_por_tipo() -> None:
    gastos = {c.value for c in categories_for(EXPENSE)}
    ingresos = {c.value for c in categories_for(INCOME)}
    assert gastos == {
        "housing",
        "groceries",
        "transport",
        "restaurants",
        "utilities",
        "health",
        "entertainment",
        "subscriptions",
        "debts",
        "uncategorized",
    }
    assert ingresos == {"salary", "freelance", "other_income", "uncategorized"}
    assert gastos | ingresos == {c.value for c in Category}
    assert categories_for(TRANSFER) == categories_for(ADJUSTMENT) == frozenset()


@pytest.mark.parametrize(
    ("tipo", "categoria", "permitida"),
    [
        (EXPENSE, Category.GROCERIES, True),
        (EXPENSE, Category.UNCATEGORIZED, True),
        (EXPENSE, Category.SALARY, False),
        (EXPENSE, None, False),
        (INCOME, Category.SALARY, True),
        (INCOME, Category.UNCATEGORIZED, True),
        (INCOME, Category.GROCERIES, False),
        (INCOME, None, False),
        (TRANSFER, None, True),
        (TRANSFER, Category.UNCATEGORIZED, False),
        (ADJUSTMENT, None, True),
        (ADJUSTMENT, Category.GROCERIES, False),
    ],
)
def test_is_allowed(tipo: TransactionType, categoria: Category | None, permitida: bool) -> None:
    assert is_allowed(tipo, categoria) is permitida


@pytest.mark.parametrize(
    ("consulta", "esperadas"),
    [
        ("mercado", {Category.GROCERIES}),
        ("SALUD", {Category.HEALTH}),
        ("categoria", {Category.UNCATEGORIZED}),  # sin tilde encuentra "Sin categoría"
        ("ingresos", {Category.OTHER_INCOME}),
        ("es", {Category.RESTAURANTS, Category.SUBSCRIPTIONS, Category.OTHER_INCOME}),
        ("", set()),
        ("   ", set()),
        ("netflix", set()),
    ],
)
def test_matching(consulta: str, esperadas: set[Category]) -> None:
    assert matching(consulta) == esperadas


# --- Búsqueda ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("texto", "normalizado"),
    [
        ("Café ÁRBOL", "cafe arbol"),
        ("Año nuevo", "ano nuevo"),
        ("  Pago   de\tla  tarjeta ", "pago de la tarjeta"),
        ("Ünïcödé", "unicode"),
        ("STRASSE straße", "strasse strasse"),  # casefold
        ("", ""),
    ],
)
def test_normalize(texto: str, normalizado: str) -> None:
    assert normalize(texto) == normalizado


def test_search_text() -> None:
    assert search_text("Mercado Éxito", "Compra del mes") == "mercado exito\ncompra del mes"
    assert search_text("Mercado", None) == "mercado"
    assert search_text(None, None) == ""


@pytest.mark.parametrize(
    ("consulta", "patron"),
    [
        ("Café", "%cafe%"),
        ("50%", "%50\\%%"),
        ("a_b", "%a\\_b%"),
        ("c:\\x", "%c:\\\\x%"),
    ],
)
def test_like_pattern_escapa_los_comodines(consulta: str, patron: str) -> None:
    assert like_pattern(consulta) == patron
