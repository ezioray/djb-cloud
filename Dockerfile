# SPDX-License-Identifier: AGPL-3.0-or-later
# DJB cloud · 最小运行镜像（FastAPI + psycopg）
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --create-home app

COPY pyproject.toml ./
COPY app ./app
COPY migrations ./migrations

RUN pip install .

USER 10001
EXPOSE 1717

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "1717"]
