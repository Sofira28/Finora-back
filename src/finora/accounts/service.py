"""Casos de uso de cuentas y tarjetas (FEAT-ACC).

Toda consulta filtra por el usuario de la sesión (RNF-ACC-01); RLS repite el filtro en la
BD (ADR-0004). Una cuenta de otro usuario se trata igual que una inexistente.
"""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from finora.accounts.models import Account, AccountType
from finora.accounts.schemas import CARD_FIELDS, CreateAccountRequest, UpdateAccountRequest
from finora.domain.money import Money
from finora.errors import ApiProblemError

# SUP-ACC-06: tope técnico para evitar abusos.
MAX_ACCOUNTS = 100

NAME_TAKEN = "Ya tienes una cuenta con ese nombre."
CARD_FIELD_MESSAGES = {
    "credit_limit": "Indica el cupo de la tarjeta.",
    "statement_day": "Elige un día entre 1 y 31.",
    "payment_due_day": "Elige un día entre 1 y 31.",
}
ONLY_FOR_CARDS = "Este dato solo aplica a tarjetas de crédito."


def _field_error(
    status: int, code: str, field: str, error_type: str, message: str
) -> ApiProblemError:
    return ApiProblemError(
        status,
        code,
        message if status != 422 else None,
        errors=[{"loc": ["body", field], "type": error_type, "message": message}],
    )


def invalid_field(field: str, error_type: str, message: str) -> ApiProblemError:
    return _field_error(422, "validation_failed", field, error_type, message)


def account_not_found() -> ApiProblemError:
    return ApiProblemError(404, "account_not_found", "No encontramos esa cuenta.")


def name_taken() -> ApiProblemError:
    return _field_error(409, "account_name_taken", "name", "name_taken", NAME_TAKEN)


def _for_storage(amount: Decimal) -> Decimal:
    return Money(amount, "COP").for_storage().amount


def movement_count(db: Session, account: Account) -> int:
    """Movimientos de la cuenta (RF-ACC-06 y 09).

    `transactions` aún no existe: ninguna cuenta tiene movimientos. Es el único punto que
    cambia cuando exista (plan.md §2).
    """
    return 0


# --- Consultas ----------------------------------------------------------------------------


def list_accounts(db: Session, user_id: uuid.UUID) -> list[Account]:
    """Activas y archivadas, en el orden en que se crearon."""
    return list(
        db.scalars(
            select(Account)
            .where(Account.user_id == user_id)
            .order_by(Account.created_at, Account.id)
        )
    )


def get_account(db: Session, user_id: uuid.UUID, account_id: uuid.UUID) -> Account:
    account = db.scalar(select(Account).where(Account.id == account_id, Account.user_id == user_id))
    if account is None:
        raise account_not_found()
    return account


def _name_in_use(
    db: Session, user_id: uuid.UUID, name: str, except_id: uuid.UUID | None = None
) -> bool:
    """VAL-ACC-02: sin distinguir mayúsculas, entre activas y archivadas."""
    query = select(Account.id).where(
        Account.user_id == user_id, func.lower(Account.name) == name.lower()
    )
    if except_id is not None:
        query = query.where(Account.id != except_id)
    return db.scalar(query.limit(1)) is not None


def _commit(db: Session) -> None:
    """Guarda; si otra petición tomó el mismo nombre entre tanto, responde lo mismo."""
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()  # descarta la cuenta nueva o los cambios a medias
        if "uq_accounts_user_id_name_lower" in str(exc.orig):
            raise name_taken() from exc
        raise


# --- Escrituras ---------------------------------------------------------------------------


def create_account(
    db: Session, user_id: uuid.UUID, data: CreateAccountRequest, now: datetime
) -> Account:
    """RF-ACC-01."""
    is_card = data.type == AccountType.CREDIT_CARD
    for field in CARD_FIELDS:
        value = getattr(data, field)
        if is_card and value is None:
            raise invalid_field(field, "missing", CARD_FIELD_MESSAGES[field])
        if not is_card and value is not None:
            raise invalid_field(field, "not_allowed", ONLY_FOR_CARDS)

    count = db.scalar(select(func.count()).select_from(Account).where(Account.user_id == user_id))
    if (count or 0) >= MAX_ACCOUNTS:
        raise ApiProblemError(
            409,
            "account_limit_reached",
            f"Llegaste al máximo de {MAX_ACCOUNTS} cuentas. Elimina las que ya no uses.",
        )
    if _name_in_use(db, user_id, data.name):
        raise name_taken()

    account = Account(
        user_id=user_id,
        name=data.name,
        type=data.type,
        institution=data.institution,
        opening_balance=_for_storage(data.opening_balance),
        credit_limit=_for_storage(data.credit_limit) if data.credit_limit is not None else None,
        statement_day=data.statement_day,
        payment_due_day=data.payment_due_day,
        created_at=now,
        updated_at=now,
    )
    db.add(account)
    _commit(db)
    return account


def update_account(
    db: Session,
    user_id: uuid.UUID,
    account_id: uuid.UUID,
    changes: UpdateAccountRequest,
    now: datetime,
) -> Account:
    """RF-ACC-05/06. El tipo no cambia (RN-ACC-08: el esquema no lo admite)."""
    account = get_account(db, user_id, account_id)
    sent = changes.model_fields_set
    is_card = account.type == AccountType.CREDIT_CARD

    for field in sent & {"name", "opening_balance", *CARD_FIELDS}:
        if field in CARD_FIELDS and not is_card:
            raise invalid_field(field, "not_allowed", ONLY_FOR_CARDS)
        if getattr(changes, field) is None:
            message = CARD_FIELD_MESSAGES.get(field, "Este dato es obligatorio.")
            raise invalid_field(field, "missing", message)

    if changes.name is not None and _name_in_use(db, user_id, changes.name, except_id=account.id):
        raise name_taken()

    if changes.opening_balance is not None:
        opening = _for_storage(changes.opening_balance)
        if opening != account.opening_balance and movement_count(db, account) > 0:
            raise ApiProblemError(
                409,
                "account_has_movements",
                "Esta cuenta ya tiene movimientos. Para corregir el saldo, registra un ajuste.",
            )
        account.opening_balance = opening

    if changes.name is not None:
        account.name = changes.name
    if "institution" in sent:
        account.institution = changes.institution
    if changes.credit_limit is not None:
        account.credit_limit = _for_storage(changes.credit_limit)
    if changes.statement_day is not None:
        account.statement_day = changes.statement_day
    if changes.payment_due_day is not None:
        account.payment_due_day = changes.payment_due_day
    account.updated_at = now
    _commit(db)
    return account


def archive_account(
    db: Session, user_id: uuid.UUID, account_id: uuid.UUID, now: datetime
) -> Account:
    """RF-ACC-07; idempotente: archivar de nuevo conserva la fecha original."""
    account = get_account(db, user_id, account_id)
    if account.archived_at is None:
        account.archived_at = now
        account.updated_at = now
        db.commit()
    return account


def restore_account(
    db: Session, user_id: uuid.UUID, account_id: uuid.UUID, now: datetime
) -> Account:
    """RF-ACC-08; idempotente."""
    account = get_account(db, user_id, account_id)
    if account.archived_at is not None:
        account.archived_at = None
        account.updated_at = now
        db.commit()
    return account


def delete_account(db: Session, user_id: uuid.UUID, account_id: uuid.UUID) -> None:
    """RF-ACC-09 y RN-ACC-10: solo sin movimientos; borrado físico y definitivo."""
    account = get_account(db, user_id, account_id)
    if movement_count(db, account) > 0:
        raise ApiProblemError(
            409,
            "account_has_movements",
            "Esta cuenta tiene movimientos. Puedes archivarla para ocultarla sin perder su "
            "historial.",
        )
    db.delete(account)
    db.commit()
