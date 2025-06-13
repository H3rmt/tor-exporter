FROM python:alpine@sha256:9b4929a72599b6c6389ece4ecbf415fd1355129f22bb92bb137eea098f05e975
RUN pip install stem prometheus_client retrying

COPY ./prometheus-tor-exporter.py /prometheus-tor-exporter.py
ENTRYPOINT ["/usr/local/bin/python", "/prometheus-tor-exporter.py"]
