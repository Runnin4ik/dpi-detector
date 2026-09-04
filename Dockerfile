FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
RUN apk add --no-cache --virtual .build-deps build-base yaml-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps \
    && adduser -D -u 1000 app

COPY app/ ./app/
COPY cli/ ./cli/
COPY core/ ./core/
COPY utils/ ./utils/
COPY dpi_detector.py .
COPY domains.txt .
COPY tcp16.json .
COPY config.yml .
COPY whitelist_sni.txt .
RUN chown -R app:app /app

USER app

ENTRYPOINT ["python", "dpi_detector.py"]