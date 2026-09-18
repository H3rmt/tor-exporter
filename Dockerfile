FROM python:alpine@sha256:016508ba505da24f7139765bc4bb669df4e88eb2f12eeadd571bf2f88d7533df
RUN pip install stem prometheus_client retrying

COPY ./prometheus-tor-exporter.py /prometheus-tor-exporter.py
ENTRYPOINT ["/usr/local/bin/python", "/prometheus-tor-exporter.py"]
