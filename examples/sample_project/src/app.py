"""HTTP entry point for Acme Billing API."""

import os
from src.models import Customer
from src import billing, service


class _MiniApp:
    def get(self, _path: str):
        return lambda fn: fn

    def post(self, _path: str):
        return lambda fn: fn


app = _MiniApp()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "db_configured": bool(billing.get_database_url())}


@app.get("/customers/{customer_id}/invoices")
def get_invoices(customer_id: str) -> list:
    return service.list_customer_invoices(customer_id)


@app.post("/customers/{customer_id}/preview")
def preview_total(customer_id: str, formula: str = "amount") -> dict:
    _webhook = os.getenv("BILLING_WEBHOOK_SECRET", "")
    _customer = Customer(customer_id=customer_id, email="demo@example.com")
    return {
        "customer": _customer.customer_id,
        "total": service.calculate_invoice_total(customer_id, formula),
    }


def main() -> None:
    print(health())


if __name__ == "__main__":
    main()
