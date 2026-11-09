from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=4, max_length=128)
    email: str | None = Field(default=None, max_length=255)


class LoginIn(BaseModel):
    username: str
    password: str


class VerifyCodeIn(BaseModel):
    username: str
    code: str = Field(min_length=1, max_length=12)


class AuthResult(BaseModel):
    """Either an access token, or a signal that an email code is required."""
    requires_code: bool = False
    access_token: str | None = None
    token_type: str = "bearer"


class ConfigOut(BaseModel):
    seed: int


class StartGameIn(BaseModel):
    seed: int


class QuestionOut(BaseModel):
    id: int
    label: str
    options: list[str]


class StartGameOut(BaseModel):
    game_id: int
    seed: int
    questions: list[QuestionOut]


class SubmitIn(BaseModel):
    game_id: int
    guesses: list[str] = Field(min_length=1, max_length=10)


class SubmitOut(BaseModel):
    score: int           # points gained this round (10 for a perfect round, else 0)
    correct_count: int   # how many of the answers were right
    correct: bool        # all answers right (full round)
    total_score: int
    balance: int


class LeaderRow(BaseModel):
    username: str
    total_score: int


class MeOut(BaseModel):
    username: str
    total_score: int
    balance: int
    has_flag: bool


class ProductOut(BaseModel):
    id: str
    name: str
    price: int
    emoji: str
    owned: bool
    purchasable: bool


class ShopOut(BaseModel):
    balance: int
    products: list[ProductOut]


class BuyIn(BaseModel):
    product_id: str


class BuyOut(BaseModel):
    product_id: str
    name: str
    message: str
    balance: int
