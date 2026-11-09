from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..config import FLAG
from ..database import get_db
from ..models import Purchase, User
from ..schemas import BuyIn, BuyOut, ProductOut, ShopOut
from ..shop import PRODUCTS, get_product, is_flag_product, is_purchasable

router = APIRouter(prefix="/api", tags=["shop"])


async def _owned_ids(db: AsyncSession, user_id: int) -> set[str]:
    result = await db.execute(select(Purchase.product_id).where(Purchase.user_id == user_id))
    return {row[0] for row in result.all()}


@router.get("/shop", response_model=ShopOut)
async def shop(user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    owned = await _owned_ids(db, user.id)
    products = [
        ProductOut(
            id=p["id"],
            name=p["name"],
            price=p["price"],
            emoji=p.get("emoji", "🛒"),
            owned=p["id"] in owned,
            purchasable=is_purchasable(p),
        )
        for p in PRODUCTS
    ]
    return ShopOut(balance=user.balance, products=products)


@router.post("/buy", response_model=BuyOut)
async def buy(
    body: BuyIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    product = get_product(body.product_id)
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Нет такого товара")

    if not is_purchasable(product):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Товар недоступен для покупки")

    owned = await _owned_ids(db, user.id)
    if product["id"] in owned:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Товар уже куплен")

    price = int(product["price"])
    if user.balance < price:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Недостаточно очков: нужно {price}, у вас {user.balance}",
        )

    user.balance -= price
    db.add(Purchase(user_id=user.id, product_id=product["id"], price=price))

    # The flag product reveals the flag read from the environment at startup.
    if is_flag_product(product):
        message = FLAG
        user.has_flag = True
    else:
        message = product.get("message", "Покупка совершена.")

    await db.commit()
    return BuyOut(
        product_id=product["id"],
        name=product["name"],
        message=message,
        balance=user.balance,
    )
