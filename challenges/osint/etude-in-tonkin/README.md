# Этюд в тонкинских тонах / A Study in Tonkin Tones (osint/easy)

- Тип: чистый OSINT, без инстанса; материалы — в `attachments/`
- Ответ: латинское название вида; флаг — `CTF{Trachypithecus poliocephalus}`
  (принимается и ответ без обёртки, сверка без учёта регистра)
- Решатель: `python3 solve.py` — автоматизирует последний шаг (нужен интернет);
  `python3 solve.py --answer '...'` — сверить свой ответ

## Условие (для игроков)

**RU:** В утренней почте лежала безымянная кассета с запиской: «Холмс, пока вы
скучаете в Лондоне, мои люди уже добрались до чудеснейших изолированных скал.
Там, среди неприступного камня, прыгают существа, чьи сверкающие головы видны
за милю. Поймать их в объектив так же сложно, как вам — выйти на мой след».
Покажите Мориарти, что отследить данный заморский вид вовсе не так уж и сложно:
найдите его официальное научное название на латыни.

**EN:** The morning mail brought an unnamed cassette with a note: "Holmes, while
you are bored in London, my people have already reached the most marvellous
isolated cliffs. There, among the inaccessible stone, leap creatures whose
gleaming heads are visible for a mile. Catching them on camera is as hard as
it is for you to follow my trail." Show Moriarty that tracing this overseas
species is not so hard after all: find its official scientific Latin name.

## Материалы

- `attachments/etude-in-tonkin-1.png` — стоп-кадр: каяки у подножия карстовых
  скал, вдали на склонах точки-силуэты;
- `attachments/etude-in-tonkin-2.png` — второй кадр той же записи, ближе к
  скалам.

## Решение

По авторскому разбору:

1. Геогесс по пейзажу: известковые карсты над изумрудной водой, каяки-туры —
   залив Халонг / остров Кат Ба, северный Вьетнам («тонкинских» в названии —
   Тонкинский залив).
2. Поиск по кадру (reverse image search) и просмотр роликов с этого района
   выводят на чёрных лангуров с бело-золотистыми «шапками» — сверкающие
   головы из записки.
3. Это эндемик Кат Ба — Cat Ba langur. Официальное научное название:
   **Trachypithecus poliocephalus** (профиль вида: eprc.asia/cat-ba-langur).
4. Альтернативный вопрос к той же находке: охранный статус вида по вьетнамскому
   законодательству — Decree 32/2006 ND-CP, группа 1B (на грани исчезновения).

Ответ: `Trachypithecus poliocephalus`. Флаг: `CTF{Trachypithecus poliocephalus}`.

## Проверка решения

```bash
python3 solve.py --answer 'Trachypithecus poliocephalus'   # сверка своего ответа
python3 solve.py                                           # последний шаг автоматом (нужен интернет)
```
