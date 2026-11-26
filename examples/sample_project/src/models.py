"""Domain models for Acme Billing API."""

from dataclasses import dataclass


@dataclass
class Invoice:
    invoice_id: str
    customer_id: str
    amount_cents: int
    currency: str = "USD"


@dataclass
class Customer:
    customer_id: str
    email: str
