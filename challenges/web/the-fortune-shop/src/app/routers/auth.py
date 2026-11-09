import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import create_access_token, get_current_user, hash_password, verify_password
from ..database import get_db
from ..models import User
from ..schemas import AuthResult, LoginIn, MeOut, RegisterIn, VerifyCodeIn

router = APIRouter(prefix="/api", tags=["auth"])


def _normalize_email(email: str | None) -> str | None:
    """Treat empty/whitespace as no email at all."""
    if email is None:
        return None
    email = email.strip()
    return email or None


@router.post("/register", response_model=AuthResult, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterIn, db: AsyncSession = Depends(get_db)):
    exists = await db.execute(select(User).where(User.username == body.username))
    if exists.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    email = _normalize_email(body.email)
    user = User(username=body.username, password_hash=hash_password(body.password), email=email)
    db.add(user)
    await db.commit()

    # No email -> no verification, log straight in. With an email, the account
    # must pass the (fake) email-code step on login.
    if email is None:
        return AuthResult(access_token=create_access_token(user.username))
    return AuthResult(requires_code=True)


@router.post("/login", response_model=AuthResult)
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Null email -> the check is skipped and the system lets the user through.
    if user.email is None:
        return AuthResult(access_token=create_access_token(user.username))

    # Email present -> generate a code and demand it. The code is intentionally
    # NOT delivered anywhere (no mail is sent).
    user.email_code = f"{secrets.randbelow(1_000_000):06d}"
    await db.commit()
    return AuthResult(requires_code=True)


@router.post("/verify_code", response_model=AuthResult)
async def verify_code(body: VerifyCodeIn, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()
    if user is None or user.email is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Code not required")
    if not user.email_code or not secrets.compare_digest(body.code, user.email_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный код")

    user.email_code = None
    await db.commit()
    return AuthResult(access_token=create_access_token(user.username))


@router.get("/me", response_model=MeOut)
async def me(user: User = Depends(get_current_user)):
    return MeOut(
        username=user.username,
        total_score=user.total_score,
        balance=user.balance,
        has_flag=user.has_flag,
    )
