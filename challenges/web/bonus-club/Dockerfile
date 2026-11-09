# Build stage: full toolchain so better-sqlite3's node-gyp fallback can
# compile when the prebuild-install download fails (runner network to
# github is flaky; node:20-slim has no python3/make/g++).
FROM node:20-slim AS build
WORKDIR /app
ENV NODE_ENV=production
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY src/app/package.json ./
RUN npm install --omit=dev && npm cache clean --force

# Runtime: slim image, native modules already built in the build stage.
FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules

COPY src/app/ ./
COPY src/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
  && mkdir -p /app/data \
  && chown -R node:node /app

USER node
EXPOSE 8090
# флаг приходит env CTF_FLAG (сидер кладёт его в служебный заказ), секрет сессий
# генерируется на старте, если не задан
HEALTHCHECK --interval=15s --timeout=4s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:8090/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/entrypoint.sh"]

# Минимальные привилегии для jury (writable: non-root USER, rw rootfs — флаг материализуется на старте)
LABEL org.innoctf.runtime=writable
