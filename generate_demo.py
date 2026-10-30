"""Generate reproducible synthetic orders and an independent expected result."""
import csv
from datetime import date, timedelta
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIELDS = ["order_id", "customer_id", "quantity", "unit_price", "ordered_on", "status", "note"]


def generate():
    folder = ROOT / "data"
    folder.mkdir(exist_ok=True)
    rows = []
    for number in range(1, 201):
        rows.append({
            "order_id": f"ORD-{number:04d}",
            "customer_id": f"C-{(number % 37) + 1:03d}",
            "quantity": str(1 + number % 7),
            "unit_price": f"{10 + number % 90}.{number % 100:02d}",
            "ordered_on": (date(2026, 1, 1) + timedelta(days=number % 90)).isoformat(),
            "status": ["paid", "pending", "refunded"][number % 3],
            "note": '合成样例，含 "引号"\n第二行备注' if number % 31 == 0 else "测试订单",
        })
    changes = {
        5: {"order_id": ""},
        18: {"quantity": "2.5"},
        29: {"unit_price": "-4.50"},
        42: {"ordered_on": "2026-02-30"},
        57: {"status": "shipping"},
        70: {"customer_id": "   "},
        88: {"unit_price": "NaN"},
        103: {"quantity": "101"},
        133: {"order_id": "ORD-0144"},
        180: {"quantity": "0", "status": "queued"},
    }
    for record, replacements in changes.items():
        rows[record - 1].update(replacements)
    with (folder / "orders.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(rows)
    rules = {
        "version": 1,
        "columns": {
            "order_id": {"type": "string", "required": True},
            "customer_id": {"type": "string", "required": True},
            "quantity": {"type": "integer", "required": True, "min": 1, "max": 100},
            "unit_price": {"type": "number", "required": True, "min": 0, "max": 10000},
            "ordered_on": {"type": "date", "required": True},
            "status": {"type": "string", "required": True, "choices": ["paid", "pending", "refunded"]},
            "note": {"type": "string"},
        },
        "unique": [["order_id"]],
    }
    expected = {
        "synthetic": True,
        "description": "200 deterministic synthetic orders with deliberately inserted errors; no real customer or transaction data.",
        "rows_total": 200,
        "rows_clean": 189,
        "rows_quarantined": 11,
        "issues_total": 12,
        "by_code": {"required": 2, "type": 3, "min": 2, "max": 1, "choices": 2, "duplicate": 2},
        "quarantined_records": [5, 18, 29, 42, 57, 70, 88, 103, 133, 144, 180],
        "injected_changes": {str(record): change for record, change in changes.items()},
        "duplicate_explanation": "Record 133 copies the order_id of record 144; both members must be quarantined.",
    }
    for filename, data in [("rules.json", rules), ("expected.json", expected)]:
        (folder / filename).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Generated 200 synthetic orders; expected 189 clean records, 11 quarantined records, 12 issues.")


if __name__ == "__main__":
    generate()
