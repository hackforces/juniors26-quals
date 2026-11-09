#!/bin/sh
# bonus-club entrypoint: сидирование БД флагом из env + запуск сервиса.
# SESSION_SECRET: из env, иначе случайный на старт (сессии живут до рестарта).
set -e

export SESSION_SECRET="${SESSION_SECRET:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}"

node seed.js
exec node server.js
