"""Endpoints /api/v1/accounts: cuentas y tarjetas (specs/api-contracts.md §5).

Solo datos del usuario de la sesión: `UserDb` fija el usuario para RLS (ADR-0004) y el
servicio filtra además por `user.id`. Los totales y el estado de las tarjetas los calcula
solo el backend (RNF-ACC-02).
"""

import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from finora.accounts import balances, service
from finora.accounts.models import Account, AccountType
from finora.accounts.schemas import (
    AccountListResponse,
    AccountResponse,
    CreateAccountRequest,
    CreditCardResponse,
    TotalsResponse,
    UpdateAccountRequest,
)
from finora.auth.dependencies import (
    ClockDep,
    CurrentUser,
    UserDb,
    purge_periodically,
    verify_request_origin,
)
from finora.domain.money import Money

router = APIRouter(
    prefix="/accounts",
    tags=["accounts"],
    dependencies=[Depends(verify_request_origin), Depends(purge_periodically)],
)


def _money(amount: Decimal) -> Money:
    return Money(amount, balances.CURRENCY)


def _api(amount: Money) -> str:
    return amount.rounded(2).to_api_string()


def _balance(db: Session, account: Account) -> Money:
    # Sin `transactions` no hay movimientos: el saldo es el inicial (RN-ACC-02).
    return balances.current_balance(_money(account.opening_balance))


def _response(db: Session, account: Account) -> AccountResponse:
    balance = _balance(db, account)
    card = None
    limit, statement, due = account.credit_limit, account.statement_day, account.payment_due_day
    if account.type == AccountType.CREDIT_CARD:
        if limit is None or statement is None or due is None:  # la tabla lo impide
            raise RuntimeError(f"Tarjeta {account.id} sin cupo o días de corte y pago")
        estado = balances.card_status(balance, _money(limit))
        card = CreditCardResponse(
            credit_limit=_api(_money(limit)),
            available_credit=_api(estado.available_credit),
            usage_percent=estado.usage_percent,
            over_limit=estado.over_limit,
            statement_day=statement,
            payment_due_day=due,
        )
    return AccountResponse(
        id=account.id,
        name=account.name,
        type=AccountType(account.type),
        institution=account.institution,
        opening_balance=_api(_money(account.opening_balance)),
        balance=_api(balance),
        has_movements=service.movement_count(db, account) > 0,
        archived=account.archived_at is not None,
        credit_card=card,
        created_at=account.created_at,
    )


@router.get("")
def list_accounts(user: CurrentUser, db: UserDb) -> AccountListResponse:
    """Activas y archivadas; los totales solo cuentan las activas (RN-ACC-03 a 05 y 09)."""
    accounts = service.list_accounts(db, user.id)
    totals = balances.totals(
        balances.AccountBalance(
            type=AccountType(a.type), balance=_balance(db, a), archived=a.archived_at is not None
        )
        for a in accounts
    )
    return AccountListResponse(
        accounts=[_response(db, a) for a in accounts],
        totals=TotalsResponse(
            available_balance=_api(totals.available_balance),
            net_worth=_api(totals.net_worth),
            credit_card_debt=_api(totals.credit_card_debt),
        ),
    )


@router.post("", status_code=status.HTTP_201_CREATED)
def create_account(
    body: CreateAccountRequest, user: CurrentUser, db: UserDb, clock: ClockDep
) -> AccountResponse:
    return _response(db, service.create_account(db, user.id, body, clock.now()))


@router.get("/{account_id}")
def get_account(account_id: uuid.UUID, user: CurrentUser, db: UserDb) -> AccountResponse:
    return _response(db, service.get_account(db, user.id, account_id))


@router.patch("/{account_id}")
def update_account(
    account_id: uuid.UUID,
    body: UpdateAccountRequest,
    user: CurrentUser,
    db: UserDb,
    clock: ClockDep,
) -> AccountResponse:
    account = service.update_account(db, user.id, account_id, body, clock.now())
    return _response(db, account)


@router.post("/{account_id}/archive")
def archive_account(
    account_id: uuid.UUID, user: CurrentUser, db: UserDb, clock: ClockDep
) -> AccountResponse:
    return _response(db, service.archive_account(db, user.id, account_id, clock.now()))


@router.post("/{account_id}/restore")
def restore_account(
    account_id: uuid.UUID, user: CurrentUser, db: UserDb, clock: ClockDep
) -> AccountResponse:
    return _response(db, service.restore_account(db, user.id, account_id, clock.now()))


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(account_id: uuid.UUID, user: CurrentUser, db: UserDb) -> None:
    service.delete_account(db, user.id, account_id)
