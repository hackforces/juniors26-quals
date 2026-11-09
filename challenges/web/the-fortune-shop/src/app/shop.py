"""Shop catalogue.

The product list is kept in a JSON variable (loaded once from shop.json). The
"flag" product carries no secret in the catalogue — its message is resolved
from the FLAG environment variable at purchase time.
"""
import json
from pathlib import Path

_SHOP_FILE = Path(__file__).resolve().parent / "shop.json"

# JSON variable holding the catalogue.
PRODUCTS: list[dict] = json.loads(_SHOP_FILE.read_text(encoding="utf-8"))

_BY_ID = {p["id"]: p for p in PRODUCTS}


def get_product(product_id: str) -> dict | None:
    return _BY_ID.get(product_id)


def is_flag_product(product: dict) -> bool:
    return bool(product.get("is_flag"))


def is_purchasable(product: dict) -> bool:
    """A product is buyable unless its catalogue entry opts out."""
    return product.get("purchasable", True)
