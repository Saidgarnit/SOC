FROM python:3.11-slim
RUN pip install requests elasticsearch --no-cache-dir
WORKDIR /app
COPY vt_enricher_fixed.py /app/vt_enricher.py
CMD ["python3", "-u", "/app/vt_enricher.py"]
