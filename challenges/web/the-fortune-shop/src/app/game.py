"""Deterministic round generation.

A round is fully derived from its integer `seed`. Each round the "correct"
answers look random (the seed is fresh every round), but they are a pure
function of the seed — and the seed is handed to the client via
/api/get_config and echoed by /api/start_game. A player who reproduces the
derivation below can answer every question correctly.

Format: 5 questions, each asking which service gets blocked in a given
timeframe. Each question shows OPTIONS_PER_Q choices; exactly one is "correct"
for that round. All 5 correct -> 100 points, a single miss -> 0.
"""
import random

QUESTIONS = [
    "Что заблокируют завтра?",
    "Что заблокируют на следующей неделе?",
    "Что заблокируют в следующем месяце?",
    "Что заблокируют в следующем году?",
    "Что никогда не заблокируют?",
]

# Популярные мессенджеры, соцсети и мемные сайты.
OPTIONS = [
    # messengers
    "Telegram", "WhatsApp", "Signal", "Viber", "Discord", "Skype",
    "WeChat", "Snapchat", "LINE", "Facebook Messenger", "iMessage",
    # social networks
    "VK", "Facebook", "Instagram", "X (Twitter)", "TikTok", "YouTube",
    "Одноклассники", "LinkedIn", "Reddit", "Pinterest", "Tumblr",
    "Mastodon", "Threads", "Twitch", "Rutube",
    # meme sites
    "Pikabu", "9GAG", "iFunny", "Imgur", "2ch", "JoyReactor",
    "Lurkmore", "4chan", "Know Your Meme",
    # мессенджеры (РФ)
    "MAX",
]

NUM_QUESTIONS = len(QUESTIONS)
OPTIONS_PER_Q = 6


def _build_round(seed: int) -> list[dict]:
    """Internal: full round including the correct option per question."""
    rng = random.Random(seed)
    questions: list[dict] = []
    for qid, label in enumerate(QUESTIONS):
        options = rng.sample(OPTIONS, OPTIONS_PER_Q)
        correct = rng.choice(options)
        questions.append({"id": qid, "label": label, "options": options, "correct": correct})
    return questions


def public_round(seed: int) -> list[dict]:
    """What the client receives — correct answers stripped out."""
    return [{"id": q["id"], "label": q["label"], "options": q["options"]} for q in _build_round(seed)]


def correct_answers(seed: int) -> list[str]:
    """The hidden answer key for a round (one option per question)."""
    return [q["correct"] for q in _build_round(seed)]


PERFECT_ROUND_POINTS = 10


def count_correct(seed: int, guesses: list[str]) -> int:
    """How many answers match, compared position by position."""
    answer = correct_answers(seed)
    return sum(1 for a, g in zip(answer, guesses) if a == g)


def score_guess(seed: int, guesses: list[str]) -> tuple[int, int]:
    """Return (points, correct_count).

    A perfect round (all NUM_QUESTIONS answered correctly) is worth
    PERFECT_ROUND_POINTS; anything less is worth 0.
    """
    correct = count_correct(seed, guesses)
    full = correct == NUM_QUESTIONS and len(guesses) == NUM_QUESTIONS
    points = PERFECT_ROUND_POINTS if full else 0
    return points, correct
