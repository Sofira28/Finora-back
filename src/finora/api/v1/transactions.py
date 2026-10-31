"""Endpoints /api/v1/transactions: movimientos (specs/api-contracts.md §6).

Solo datos del usuario de la sesión: `UserDb` fija el usuario para RLS (ADR-0004) y el
servicio filtra además por `user.id`. El resumen y los saldos los calcula solo el backend
(RNF-TRX-02).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from finora.auth.dependencies import (
    ClockDep,
    CurrentUser,
    UserDb,
    purge_periodically,
    verify_request_origin,
)
from finora.domain.money import Money
from finora.transactions import service
from finora.transactions.models import Category, Transaction, TransactionType
from finora.transactions.schemas import (
    AccountingDate,
    SummaryResponse,
    TransactionPageResponse,
    TransactionRequest,
    TransactionResponse,
)
from finora.transactions.service import Filters, Sort

router = APIRouter(
    prefix="/transactions",
    tags=["transactions"],
    dependencies=[Depends(verify_request_origin), Depends(purge_periodically)],
)

QUERY_MAX = 100
CURSOR_MAX = 512


def _api(amount: Money) -> str:
    return amount.rounded(2).to_api_string()


def _response(transaction: Transaction) -> TransactionResponse:
    return TransactionResponse(
        id=transaction.id,
        type=TransactionType(transaction.type),
        amount=_api(Money(transaction.amount, service.CURRENCY)),
        date=transaction.occurred_on,
        account_id=transaction.account_id,
        destination_account_id=transaction.destination_account_id,
        category=Category(transaction.category) if transaction.category is not None else None,
        description=transaction.description,
        note=transaction.note,
        created_at=transaction.created_at,
        updated_at=transaction.updated_at,
    )


@router.get("")
def list_transactions(
    user: CurrentUser,
    db: UserDb,
    q: Annotated[str | None, Query(max_length=QUERY_MAX)] = None,
    from_date: Annotated[AccountingDate | None, Query(alias="from")] = None,
    to_date: Annotated[AccountingDate | None, Query(alias="to")] = None,
    type: TransactionType | None = None,
    category: Category | None = None,
    account_id: uuid.UUID | None = None,
    sort: Sort = Sort.DATE_DESC,
    cursor: Annotated[str | None, Query(max_length=CURSOR_MAX)] = None,
    limit: Annotated[int, Query(ge=1, le=service.MAX_LIMIT)] = service.DEFAULT_LIMIT,
) -> TransactionPageResponse:
    """RF-TRX-04 a 06: página, total y resumen de todo lo que cumple los filtros."""
    filters = Filters(
        q=q,
        from_date=from_date,
        to_date=to_date,
        type=type,
        category=category,
        account_id=account_id,
    )
    page = service.list_transactions(db, user.id, filters, sort, cursor=cursor, limit=limit)
    summary = page.summary
    return TransactionPageResponse(
        items=[_response(t) for t in page.items],
        total=page.total,
        next_cursor=page.next_cursor,
        summary=SummaryResponse(
            count=summary.count,
            income=_api(summary.income),
            expense=_api(summary.expense),
            savings=_api(summary.savings),
            transfers=_api(summary.transfers),
        ),
    )


@router.post("", status_code=status.HTTP_201_CREATED)
def create_transaction(
    body: TransactionRequest, user: CurrentUser, db: UserDb, clock: ClockDep
) -> TransactionResponse:
    return _response(service.create_transaction(db, user.id, body, clock.now()))


@router.get("/{transaction_id}")
def get_transaction(
    transaction_id: uuid.UUID, user: CurrentUser, db: UserDb
) -> TransactionResponse:
    return _response(service.get_transaction(db, user.id, transaction_id))


@router.put("/{transaction_id}")
def replace_transaction(
    transaction_id: uuid.UUID,
    body: TransactionRequest,
    user: CurrentUser,
    db: UserDb,
    clock: ClockDep,
) -> TransactionResponse:
    """RF-TRX-07: reemplazo completo; el tipo puede cambiar."""
    transaction = service.replace_transaction(db, user.id, transaction_id, body, clock.now())
    return _response(transaction)


@router.delete("/{transaction_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_transaction(transaction_id: uuid.UUID, user: CurrentUser, db: UserDb) -> None:
    service.delete_transaction(db, user.id, transaction_id)
