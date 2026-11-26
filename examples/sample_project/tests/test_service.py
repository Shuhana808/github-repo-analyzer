"""Unit tests for Acme Billing API."""

from src import service


def test_list_customer_invoices():
    invoices = service.list_customer_invoices("cust_1")
    assert len(invoices) == 1
    assert invoices[0].amount_cents == 2500
