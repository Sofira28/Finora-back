"""Tipo monetario de FINORA.

Reglas (ADR-0001, FEAT-SETUP):
- Nunca se usa ``float`` para dinero: solo ``Decimal``, ``int`` o cadenas decimales.
- Todo monto lleva su moneda (ISO 4217) y no se operan monedas distintas.
- El redondeo es siempre explícito y usa ``ROUND_HALF_EVEN``.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

# Monedas habilitadas; inicialmente solo COP.
SUPPORTED_CURRENCIES = frozenset({"COP"})

# Decimales con los que se persiste un monto (NUMERIC(19,4)).
STORAGE_PLACES = 4

# Máximo absoluto representable en NUMERIC(19,4): 15 dígitos enteros.
_MAX_ABS_STORAGE = Decimal("1e15")

type AmountInput = Decimal | int | str


class CurrencyMismatchError(ValueError):
    """Se intentó operar montos de monedas distintas."""


def _to_decimal(value: AmountInput) -> Decimal:
    # bool es subclase de int y float no es seguro: ambos se rechazan.
    if isinstance(value, bool) or not isinstance(value, Decimal | int | str):
        raise TypeError(f"Monto no admitido: {type(value).__name__}; use Decimal, int o str.")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"Monto inválido: {value!r}") from exc
    if not result.is_finite():
        raise ValueError(f"Monto no finito: {value!r}")
    return result


@dataclass(frozen=True, slots=True)
class Money:
    amount: Decimal
    currency: str

    def __init__(self, amount: AmountInput, currency: str) -> None:
        if currency not in SUPPORTED_CURRENCIES:
            raise ValueError(f"Moneda no soportada: {currency!r}")
        object.__setattr__(self, "amount", _to_decimal(amount))
        object.__setattr__(self, "currency", currency)

    @classmethod
    def zero(cls, currency: str) -> Money:
        return cls(Decimal(0), currency)

    def _check_same_currency(self, other: Money) -> None:
        if self.currency != other.currency:
            raise CurrencyMismatchError(f"No se pueden operar {self.currency} y {other.currency}.")

    def __add__(self, other: Money) -> Money:
        if not isinstance(other, Money):
            return NotImplemented
        self._check_same_currency(other)
        return Money(self.amount + other.amount, self.currency)

    def __sub__(self, other: Money) -> Money:
        if not isinstance(other, Money):
            return NotImplemented
        self._check_same_currency(other)
        return Money(self.amount - other.amount, self.currency)

    def __neg__(self) -> Money:
        return Money(-self.amount, self.currency)

    def __mul__(self, factor: Decimal | int) -> Money:
        # Multiplicar por tasas o cantidades; el resultado no se redondea solo.
        if isinstance(factor, bool) or not isinstance(factor, Decimal | int):
            return NotImplemented
        return Money(self.amount * _to_decimal(factor), self.currency)

    __rmul__ = __mul__

    def __lt__(self, other: Money) -> bool:
        self._check_same_currency(other)
        return self.amount < other.amount

    def __le__(self, other: Money) -> bool:
        self._check_same_currency(other)
        return self.amount <= other.amount

    def __gt__(self, other: Money) -> bool:
        self._check_same_currency(other)
        return self.amount > other.amount

    def __ge__(self, other: Money) -> bool:
        self._check_same_currency(other)
        return self.amount >= other.amount

    def is_negative(self) -> bool:
        return self.amount < 0

    def rounded(self, places: int) -> Money:
        """Redondea a ``places`` decimales con ROUND_HALF_EVEN."""
        if places < 0:
            raise ValueError("places debe ser >= 0")
        exponent = Decimal(1).scaleb(-places)
        return Money(self.amount.quantize(exponent, rounding=ROUND_HALF_EVEN), self.currency)

    def for_storage(self) -> Money:
        """Monto listo para NUMERIC(19,4); falla si excede el rango."""
        result = self.rounded(STORAGE_PLACES)
        if abs(result.amount) >= _MAX_ABS_STORAGE:
            raise ValueError("Monto fuera del rango almacenable (NUMERIC(19,4)).")
        return result

    def to_api_string(self) -> str:
        """Cadena decimal sin notación científica, para el payload de la API."""
        return format(self.amount, "f")
