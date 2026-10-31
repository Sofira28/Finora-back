"""Catálogo fijo de categorías (FEAT-TRX, RN-TRX-07, CD-10).

Las claves y qué categorías corresponden a cada tipo están en `models` (las usa también
el `CHECK` de la tabla); aquí van los nombres para el usuario y las consultas. `budgets`
reemplazará este catálogo por categorías propias (PA-BUD-01).
"""

from finora.transactions.models import (
    EXPENSE_CATEGORIES,
    INCOME_CATEGORIES,
    Category,
    TransactionType,
)
from finora.transactions.search import normalize

# Nombres en es-CO, como en Claude Design.
LABELS: dict[Category, str] = {
    Category.HOUSING: "Vivienda",
    Category.GROCERIES: "Mercado",
    Category.TRANSPORT: "Transporte",
    Category.RESTAURANTS: "Restaurantes",
    Category.UTILITIES: "Servicios",
    Category.HEALTH: "Salud",
    Category.ENTERTAINMENT: "Entretenimiento",
    Category.SUBSCRIPTIONS: "Suscripciones",
    Category.DEBTS: "Deudas",
    Category.SALARY: "Salario",
    Category.FREELANCE: "Freelance",
    Category.OTHER_INCOME: "Otros ingresos",
    Category.UNCATEGORIZED: "Sin categoría",
}

_BY_TYPE: dict[TransactionType, frozenset[Category]] = {
    TransactionType.EXPENSE: EXPENSE_CATEGORIES,
    TransactionType.INCOME: INCOME_CATEGORIES,
}


def categories_for(type: TransactionType) -> frozenset[Category]:
    """Categorías permitidas en el tipo; vacío si el tipo no lleva categoría."""
    return _BY_TYPE.get(type, frozenset())


def is_allowed(type: TransactionType, category: Category | None) -> bool:
    """VAL-TRX-06 y 11: obligatoria y del tipo en gastos e ingresos; ausente en los demás."""
    allowed = categories_for(type)
    if not allowed:
        return category is None
    return category in allowed


def matching(query: str) -> frozenset[Category]:
    """Categorías cuyo nombre contiene `query`, sin distinguir mayúsculas ni tildes.

    La búsqueda de movimientos las agrega como `category IN (...)` (plan.md §2).
    """
    needle = normalize(query)
    if not needle:
        return frozenset()
    return frozenset(c for c, label in LABELS.items() if needle in normalize(label))
