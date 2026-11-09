import secrets

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..database import get_db
from ..game import NUM_QUESTIONS, public_round, score_guess
from ..models import Game, User
from ..schemas import (
    ConfigOut,
    LeaderRow,
    StartGameIn,
    StartGameOut,
    SubmitIn,
    SubmitOut,
)

router = APIRouter(prefix="/api", tags=["game"])

SEED_MAX = 2**31 - 1


@router.get("/get_config", response_model=ConfigOut)
async def get_config(user: User = Depends(get_current_user)):
    """Hand out a fresh seed. The whole round is derived from it."""
    return ConfigOut(seed=secrets.randbelow(SEED_MAX) + 1)


@router.post("/start_game", response_model=StartGameOut)
async def start_game(
    body: StartGameIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not (1 <= body.seed <= SEED_MAX):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid seed")

    game = Game(user_id=user.id, seed=body.seed)
    db.add(game)
    await db.commit()
    await db.refresh(game)

    return StartGameOut(
        game_id=game.id,
        seed=game.seed,
        questions=public_round(game.seed),
    )


@router.post("/submit", response_model=SubmitOut)
async def submit(
    body: SubmitIn,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Game).where(Game.id == body.game_id))
    game = result.scalar_one_or_none()
    if game is None or game.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Game not found")
    if game.finished:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Game already finished")

    points, correct_count = score_guess(game.seed, body.guesses)
    game.score = points
    game.finished = True
    if points:
        user.total_score += points
        user.balance += points  # points double as shop currency

    await db.commit()
    return SubmitOut(
        score=points,
        correct_count=correct_count,
        correct=correct_count == NUM_QUESTIONS,
        total_score=user.total_score,
        balance=user.balance,
    )


@router.get("/leaderboard", response_model=list[LeaderRow])
async def leaderboard(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User.username, User.total_score).order_by(desc(User.total_score), User.id).limit(20)
    )
    return [LeaderRow(username=u, total_score=s) for u, s in result.all()]
