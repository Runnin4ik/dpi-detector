FROM python:3.14-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cli/ ./cli/
COPY core/ ./core/
COPY utils/ ./utils/
COPY dpi_detector.py .
COPY domains.txt .
COPY tcp16.json .
COPY config.yml .
COPY whitelist_sni.txt .

CMD ["python", "dpi_detector.py"]