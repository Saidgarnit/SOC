FROM python:3.11-slim
RUN pip install requests elasticsearch --no-cache-dir
WORKDIR /app
COPY vt_enricher.py /app/vt_enricher.py
COPY misp_ioc_sync.py /app/misp_ioc_sync.py
ENV POLL_INTERVAL=300
CMD ["python3", "-u", "/app/vt_enricher.py"]
