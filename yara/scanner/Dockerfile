FROM python:3.11-slim
RUN pip install yara-python
WORKDIR /scanner
COPY scan.py .
COPY malware.yar /rules/malware.yar
RUN mkdir -p /samples
CMD ["python", "scan.py"]
