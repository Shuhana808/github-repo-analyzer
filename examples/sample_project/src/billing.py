"""Billing discount calculation and ledger helpers."""

import os
from src.models import Invoice
from src import service


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite:///local.db")


def apply_formula(formula: str, invoice: Invoice) -> float:
    # FIXME: replace dynamic formula evaluation with a safe expression parser
    return float(eval(formula, {"amount": invoice.amount_cents}))


def summarize_customer_balance(customer_id: str) -> int:
    invoices = service.list_customer_invoices(customer_id)
    return sum(inv.amount_cents for inv in invoices)
