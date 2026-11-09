from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .database import init_db
from .game import NUM_QUESTIONS
from .routers import auth as auth_router
from .routers import game as game_router
from .routers import shop as shop_router

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Лавка предсказаний")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.include_router(auth_router.router)
app.include_router(game_router.router)
app.include_router(shop_router.router)


@app.on_event("startup")
async def _startup() -> None:
    await init_db()


def _page(request: Request, name: str, **ctx):
    base = {"request": request, "num_questions": NUM_QUESTIONS}
    return templates.TemplateResponse(name, {**base, **ctx})


@app.get("/")
async def index(request: Request):
    return _page(request, "index.html", title="Лавка предсказаний")


@app.get("/login")
async def login_page(request: Request):
    return _page(request, "login.html", title="Вход")


@app.get("/register")
async def register_page(request: Request):
    return _page(request, "register.html", title="Регистрация")


@app.get("/play")
async def play_page(request: Request):
    return _page(request, "game.html", title="Игра")


@app.get("/shop")
async def shop_page(request: Request):
    return _page(request, "shop.html", title="Магазин")


@app.get("/leaderboard")
async def leaderboard_page(request: Request):
    return _page(request, "leaderboard.html", title="Таблица лидеров")
