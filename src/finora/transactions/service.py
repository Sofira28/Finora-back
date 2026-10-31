"""Casos de uso de movimientos (FEAT-TRX).

Toda consulta filtra por el usuario de la sesión (RNF-TRX-01); RLS y las FK compuestas lo
repiten en la BD (ADR-0004 y 0005). Un movimiento de otro usuario se trata igual que uno
inexistente, y una cuenta ajena en la petición, igual que una que no existe.
"""

import base64
import binascii
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import ColumnElement, and_, case, func, not_, or_, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import InstrumentedAttribute, Session, aliased

from finora.accounts.models import Account
from finora.domain.money import Money
from finora.errors import ApiProblemError
from finora.transactions import categories
from finora.transactions.effects import SAVINGS_TYPES
from finora.transactions.ledger import effects_by_account
from finora.transactions.models import MIN_DATE, Category, Transaction, TransactionType
from finora.transactions.schemas import TransactionRequest
from finora.transactions.search import like_pattern, normalize, search_text

CURRENCY = "COP"
# Día contable (DP-DB-07): "hoy" es el día en Colombia, no en UTC.
ACCOUNTING_TZ = ZoneInfo("America/Bogota")

DEFAULT_LIMIT = 50
MAX_LIMIT = 100
# Lo que cabe en NUMERIC(19,4) (SUP-TRX-01): un ajuste es una diferencia de dos saldos.
MAX_ABS_AMOUNT = Decimal(10) ** 15

# Mensajes de la spec §10.
AMOUNT_MESSAGE = "Escribe un monto mayor que cero, p. ej. 1.250.000."
TARGET_MESSAGE = "Escribe el saldo real de la cuenta, p. ej. 1.250.000."
DATE_MESSAGE = "Elige una fecha entre el 01/01/2000 y hoy."
ACCOUNT_MESSAGE = "Elige una de tus cuentas."
ARCHIVED_MESSAGE = "Esta cuenta está archivada. Reactívala para registrar movimientos."
DESTINATION_MESSAGE = "Elige una cuenta de destino distinta a la de origen."
CATEGORY_MESSAGE = "Elige una categoría."
DESCRIPTION_MESSAGE = "Escribe una descripción de hasta 80 caracteres."
SAME_BALANCE_MESSAGE = "Ese ya es el saldo de la cuenta."
NOT_ALLOWED_MESSAGE = "Este dato no aplica a este tipo de movimiento."
RANGE_MESSAGE = "La fecha inicial no puede ser posterior a la final."
CURSOR_MESSAGE = "La lista cambió. Vuelve a cargarla."

# Campos de cada tipo (api-contracts.md §6.3): obligatorios y opcionales. `date` y
# `account_id` los exige siempre el esquema.
_REQUIRED: dict[TransactionType, tuple[str, ...]] = {
    TransactionType.EXPENSE: ("amount", "category", "description"),
    TransactionType.INCOME: ("amount", "category", "description"),
    TransactionType.TRANSFER: ("amount", "destination_account_id"),
    TransactionType.ADJUSTMENT: ("target_balance",),
}
_OPTIONAL: dict[TransactionType, tuple[str, ...]] = {
    TransactionType.EXPENSE: ("note",),
    TransactionType.INCOME: ("note",),
    TransactionType.TRANSFER: ("description", "note"),
    TransactionType.ADJUSTMENT: ("description", "note"),
}
_BY_TYPE_FIELDS = ("amount", "target_balance", "destination_account_id", "category", "description")
_MISSING_MESSAGES = {
    "amount": AMOUNT_MESSAGE,
    "target_balance": TARGET_MESSAGE,
    "destination_account_id": DESTINATION_MESSAGE,
    "category": CATEGORY_MESSAGE,
    "description": DESCRIPTION_MESSAGE,
}


def _error(location: str, field: str, error_type: str, message: str) -> ApiProblemError:
    return ApiProblemError(
        422,
        "validation_failed",
        errors=[{"loc": [location, field], "type": error_type, "message": message}],
    )


def invalid_field(field: str, error_type: str, message: str) -> ApiProblemError:
    return _error("body", field, error_type, message)


def invalid_query(field: str, error_type: str, message: str) -> ApiProblemError:
    return _error("query", field, error_type, message)


def transaction_not_found() -> ApiProblemError:
    return ApiProblemError(404, "transaction_not_found", "No encontramos ese movimiento.")


def today(now: datetime) -> date:
    """Día contable de `now` en Colombia (RN-TRX-09)."""
    return now.astimezone(ACCOUNTING_TZ).date()


def _for_storage(amount: Decimal | Money) -> Decimal:
    money = amount if isinstance(amount, Money) else Money(amount, CURRENCY)
    return money.for_storage().amount


# --- Validación de una petición -----------------------------------------------------------


def _check_fields(data: TransactionRequest) -> None:
    """VAL-TRX-01, 05 a 07 y 11: qué campos lleva cada tipo."""
    required, optional = _REQUIRED[data.type], _OPTIONAL[data.type]
    for field in _BY_TYPE_FIELDS:
        value = getattr(data, field)
        if field in required and value is None:
            raise invalid_field(field, "missing", _MISSING_MESSAGES[field])
        if field not in required and field not in optional and value is not None:
            raise invalid_field(field, "not_allowed", NOT_ALLOWED_MESSAGE)
    if data.category is not None and not categories.is_allowed(data.type, data.category):
        raise invalid_field("category", "category_mismatch", CATEGORY_MESSAGE)


def _account(
    db: Session,
    user_id: uuid.UUID,
    field: str,
    account_id: uuid.UUID,
    current_id: uuid.UUID | None,
) -> Account:
    """VAL-TRX-03 y 04. Al editar se acepta la cuenta archivada que el campo ya tenía."""
    account = db.scalar(select(Account).where(Account.id == account_id, Account.user_id == user_id))
    if account is None:
        raise invalid_field(field, "account_not_found", ACCOUNT_MESSAGE)
    if account.archived_at is not None and account.id != current_id:
        raise invalid_field(field, "account_archived", ARCHIVED_MESSAGE)
    return account


def _adjustment_amount(
    db: Session,
    user_id: uuid.UUID,
    account: Account,
    target: Decimal,
    current: Transaction | None,
) -> Decimal:
    """RN-TRX-04: diferencia entre el saldo real y el actual, sin contar el propio ajuste."""
    exclude = current.id if current is not None else None
    effects = effects_by_account(db, user_id, [account.id], exclude_id=exclude)
    balance = Money(account.opening_balance, CURRENCY) + effects.get(
        account.id, Money.zero(CURRENCY)
    )
    difference = Money(target, CURRENCY) - balance
    if difference.amount == 0:
        raise invalid_field("target_balance", "same_balance", SAME_BALANCE_MESSAGE)
    if abs(difference.amount) >= MAX_ABS_AMOUNT:
        raise invalid_field("target_balance", "out_of_range", TARGET_MESSAGE)
    return _for_storage(difference)


def _values(
    db: Session,
    user_id: uuid.UUID,
    data: TransactionRequest,
    now: datetime,
    current: Transaction | None = None,
) -> dict[str, Any]:
    """Columnas del movimiento tras aplicar las reglas de la spec §8 y §10."""
    _check_fields(data)
    if not MIN_DATE <= data.date <= today(now):
        raise invalid_field("date", "date_out_of_range", DATE_MESSAGE)

    account = _account(
        db, user_id, "account_id", data.account_id, current.account_id if current else None
    )
    destination_id = data.destination_account_id
    if destination_id is not None:
        if destination_id == account.id:
            raise invalid_field("destination_account_id", "same_account", DESTINATION_MESSAGE)
        _account(
            db,
            user_id,
            "destination_account_id",
            destination_id,
            current.destination_account_id if current else None,
        )

    # _check_fields ya exigió `target_balance` en ajustes y `amount` en los demás tipos.
    if data.target_balance is not None:
        amount = _adjustment_amount(db, user_id, account, data.target_balance, current)
    elif data.amount is not None:
        amount = _for_storage(data.amount)
    else:  # pragma: no cover
        raise invalid_field("amount", "missing", AMOUNT_MESSAGE)

    return {
        "type": data.type.value,
        "amount": amount,
        "occurred_on": data.date,
        "account_id": account.id,
        "destination_account_id": destination_id,
        "category": data.category.value if data.category is not None else None,
        "description": data.description,
        "note": data.note,
        "search_text": search_text(data.description, data.note),
    }


def _commit(db: Session) -> None:
    """Guarda; si una cuenta se borró entre tanto, la FK compuesta lo detecta."""
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        message = str(exc.orig)
        if "fk_transactions_destination_account_id" in message:
            raise invalid_field(
                "destination_account_id", "account_not_found", ACCOUNT_MESSAGE
            ) from exc
        if "fk_transactions_account_id" in message:
            raise invalid_field("account_id", "account_not_found", ACCOUNT_MESSAGE) from exc
        raise


# --- Escrituras ---------------------------------------------------------------------------


def create_transaction(
    db: Session, user_id: uuid.UUID, data: TransactionRequest, now: datetime
) -> Transaction:
    """RF-TRX-01 a 03."""
    transaction = Transaction(
        user_id=user_id, **_values(db, user_id, data, now), created_at=now, updated_at=now
    )
    db.add(transaction)
    _commit(db)
    return transaction


def replace_transaction(
    db: Session,
    user_id: uuid.UUID,
    transaction_id: uuid.UUID,
    data: TransactionRequest,
    now: datetime,
) -> Transaction:
    """RF-TRX-07: reemplazo completo; el tipo puede cambiar."""
    transaction = get_transaction(db, user_id, transaction_id)
    for column, value in _values(db, user_id, data, now, transaction).items():
        setattr(transaction, column, value)
    transaction.updated_at = now
    _commit(db)
    return transaction


def delete_transaction(db: Session, user_id: uuid.UUID, transaction_id: uuid.UUID) -> None:
    """RF-TRX-08: definitivo; los saldos se recalculan solos (se calculan al leer)."""
    db.delete(get_transaction(db, user_id, transaction_id))
    db.commit()


# --- Consultas ----------------------------------------------------------------------------


def get_transaction(db: Session, user_id: uuid.UUID, transaction_id: uuid.UUID) -> Transaction:
    transaction = db.scalar(
        select(Transaction).where(Transaction.id == transaction_id, Transaction.user_id == user_id)
    )
    if transaction is None:
        raise transaction_not_found()
    return transaction


class Sort(StrEnum):
    DATE_DESC = "date_desc"
    DATE_ASC = "date_asc"
    AMOUNT_DESC = "amount_desc"
    AMOUNT_ASC = "amount_asc"


@dataclass(frozen=True)
class Filters:
    """RF-TRX-05. `None` = sin ese filtro."""

    q: str | None = None
    from_date: date | None = None
    to_date: date | None = None
    type: TransactionType | None = None
    category: Category | None = None
    account_id: uuid.UUID | None = None


@dataclass(frozen=True)
class Summary:
    """RN-TRX-05."""

    count: int
    income: Money
    expense: Money
    savings: Money
    transfers: Money


@dataclass(frozen=True)
class Page:
    items: list[Transaction]
    total: int
    next_cursor: str | None
    summary: Summary


def _conditions(db: Session, user_id: uuid.UUID, filters: Filters) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [Transaction.user_id == user_id]
    if filters.from_date is not None:
        conditions.append(Transaction.occurred_on >= filters.from_date)
    if filters.to_date is not None:
        conditions.append(Transaction.occurred_on <= filters.to_date)
    if filters.type is not None:
        conditions.append(Transaction.type == filters.type.value)
    if filters.category is not None:
        conditions.append(Transaction.category == filters.category.value)
    if filters.account_id is not None:
        conditions.append(
            or_(
                Transaction.account_id == filters.account_id,
                Transaction.destination_account_id == filters.account_id,
            )
        )
    if filters.q is not None and normalize(filters.q):
        conditions.append(_search(db, user_id, filters.q))
    return conditions


def _search(db: Session, user_id: uuid.UUID, q: str) -> ColumnElement[bool]:
    """SUP-TRX-04: descripción, nota, nombre de la categoría o de la cuenta.

    Categorías y cuentas son pocas: se buscan en Python y se agregan como `IN (...)`
    (plan.md §2), sin depender de `unaccent`.
    """
    needle = normalize(q)
    options: list[ColumnElement[bool]] = [
        Transaction.search_text.like(like_pattern(q), escape="\\")
    ]
    found_categories = categories.matching(q)
    if found_categories:
        options.append(Transaction.category.in_([c.value for c in found_categories]))
    accounts = db.execute(select(Account.id, Account.name).where(Account.user_id == user_id))
    account_ids = [id_ for id_, name in accounts if needle in normalize(name)]
    if account_ids:
        options.append(Transaction.account_id.in_(account_ids))
        options.append(Transaction.destination_account_id.in_(account_ids))
    return or_(*options)


def _summary(conditions: list[ColumnElement[bool]], db: Session) -> Summary:
    origin, destination = aliased(Account), aliased(Account)
    savings_types = [t.value for t in SAVINGS_TYPES]
    is_transfer = Transaction.type == TransactionType.TRANSFER.value
    to_savings = and_(
        is_transfer, destination.type.in_(savings_types), origin.type.not_in(savings_types)
    )
    from_savings = and_(
        is_transfer, origin.type.in_(savings_types), destination.type.not_in(savings_types)
    )

    def total(expression: ColumnElement[Any]) -> ColumnElement[Decimal]:
        return func.coalesce(func.sum(expression), 0)

    row = db.execute(
        select(
            func.count(),
            total(case((Transaction.type == TransactionType.INCOME.value, Transaction.amount))),
            total(case((Transaction.type == TransactionType.EXPENSE.value, Transaction.amount))),
            total(
                case(
                    (to_savings, Transaction.amount),
                    (from_savings, -Transaction.amount),
                )
            ),
            total(
                case((and_(is_transfer, not_(to_savings), not_(from_savings)), Transaction.amount))
            ),
        )
        .select_from(Transaction)
        .join(origin, origin.id == Transaction.account_id)
        .outerjoin(destination, destination.id == Transaction.destination_account_id)
        .where(*conditions)
    ).one()
    count, income, expense, savings, transfers = row
    return Summary(
        count=count,
        income=Money(income, CURRENCY),
        expense=Money(expense, CURRENCY),
        savings=Money(savings, CURRENCY),
        transfers=Money(transfers, CURRENCY),
    )


# --- Orden y cursor (DP-API-06) -----------------------------------------------------------


def _sort_columns(sort: Sort) -> list[ColumnElement[Any] | InstrumentedAttribute[Any]]:
    """Clave de orden, con desempate estable en el mismo sentido."""
    if sort in (Sort.AMOUNT_DESC, Sort.AMOUNT_ASC):
        # Por valor absoluto: un ajuste de -500.000 queda junto a los de 500.000.
        return [func.abs(Transaction.amount), Transaction.created_at, Transaction.id]
    return [Transaction.occurred_on, Transaction.created_at, Transaction.id]


def _key(sort: Sort, transaction: Transaction) -> list[str]:
    first = (
        str(abs(transaction.amount))
        if sort in (Sort.AMOUNT_DESC, Sort.AMOUNT_ASC)
        else transaction.occurred_on.isoformat()
    )
    return [first, transaction.created_at.isoformat(), str(transaction.id)]


def _parse_key(sort: Sort, values: list[str]) -> tuple[Any, ...]:
    first, created_at, id_ = values
    parsed_first: Any = (
        Decimal(first) if sort in (Sort.AMOUNT_DESC, Sort.AMOUNT_ASC) else date.fromisoformat(first)
    )
    return (parsed_first, datetime.fromisoformat(created_at), uuid.UUID(id_))


def _fingerprint(filters: Filters) -> str:
    """Identifica los filtros: un cursor solo sirve con los mismos con que se creó."""
    data = [
        normalize(filters.q or ""),
        str(filters.from_date),
        str(filters.to_date),
        str(filters.type),
        str(filters.category),
        str(filters.account_id),
    ]
    return hashlib.sha256(json.dumps(data).encode()).hexdigest()[:16]


def encode_cursor(sort: Sort, filters: Filters, transaction: Transaction) -> str:
    payload = {"s": sort.value, "f": _fingerprint(filters), "k": _key(sort, transaction)}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str, sort: Sort, filters: Filters) -> tuple[Any, ...]:
    """Clave del último movimiento de la página anterior; 422 si no corresponde."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        payload = json.loads(raw)
        if payload["s"] != sort.value or payload["f"] != _fingerprint(filters):
            raise ValueError("cursor de otra consulta")
        return _parse_key(sort, payload["k"])
    except (binascii.Error, UnicodeDecodeError, ValueError, KeyError, TypeError) as exc:
        raise invalid_query("cursor", "invalid_cursor", CURSOR_MESSAGE) from exc


def list_transactions(
    db: Session,
    user_id: uuid.UUID,
    filters: Filters,
    sort: Sort = Sort.DATE_DESC,
    cursor: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> Page:
    """RF-TRX-04 a 06: página, total y resumen de todo lo que cumple los filtros."""
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit debe estar entre 1 y {MAX_LIMIT}")
    if (
        filters.from_date is not None
        and filters.to_date is not None
        and filters.from_date > filters.to_date
    ):
        raise invalid_query("from", "invalid_range", RANGE_MESSAGE)

    conditions = _conditions(db, user_id, filters)
    summary = _summary(conditions, db)

    columns = _sort_columns(sort)
    descending = sort in (Sort.DATE_DESC, Sort.AMOUNT_DESC)
    query = select(Transaction).where(*conditions)
    if cursor is not None:
        after = tuple_(*columns)
        last = tuple_(*decode_cursor(cursor, sort, filters))
        query = query.where(after < last if descending else after > last)
    query = query.order_by(*(c.desc() if descending else c.asc() for c in columns))

    rows = list(db.scalars(query.limit(limit + 1)))
    items = rows[:limit]
    next_cursor = encode_cursor(sort, filters, items[-1]) if len(rows) > limit else None
    return Page(items=items, total=summary.count, next_cursor=next_cursor, summary=summary)
