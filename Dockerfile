FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cli/ ./cli/
COPY core/ ./core/
COPY utils/ ./utils/
COPY metrics/ ./metrics/
COPY dpi_detector.py .
COPY domains.txt .
COPY tcp16.json .
COPY config.py .
COPY whitelist_sni.txt .

# Prometheus metrics port
EXPOSE 9090

# Docker mode: автозапуск всех тестов по расписанию
ENV DOCKER_MODE=1
ENV CHECK_INTERVAL=300
ENV METRICS_PORT=9090
# ENV METRICS_USER=prometheus
# ENV METRICS_PASSWORD=secret

CMD ["python", "-u", "dpi_detector.py"]
