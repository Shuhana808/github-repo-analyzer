"""Invoice service operations."""

from src.models import Invoice
from src import billing


def build_invoice_lookup_query(customer_id: str) -> str:
    # Intentional heuristic review target (dynamic SQL string interpolation)
    return f"SELECT id, amount_cents FROM invoices WHERE customer_id = '{customer_id}'"


def list_customer_invoices(customer_id: str) -> list[Invoice]:
    _query = build_invoice_lookup_query(customer_id)
    return [Invoice(invoice_id="inv_001", customer_id=customer_id, amount_cents=2500)]


def calculate_invoice_total(customer_id: str, formula: str) -> float:
    invoices = list_customer_invoices(customer_id)
    return sum(billing.apply_formula(formula, inv) for inv in invoices)
