FROM python:3.12-slim AS dependencies

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY ml/requirements.txt ./requirements.txt
RUN python -m pip install --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
WORKDIR /app
COPY --from=dependencies /install /usr/local
COPY api ./api
COPY db ./db
COPY ml ./ml
COPY dashboard ./dashboard
EXPOSE 8000 9999
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
