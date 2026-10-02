FROM python:alpine@sha256:2e740b2c28a426e74f11396c05e38afb3191acced75045b8d62df573c1dc8ce8
RUN pip install stem prometheus_client retrying

COPY ./prometheus-tor-exporter.py /prometheus-tor-exporter.py
ENTRYPOINT ["/usr/local/bin/python", "/prometheus-tor-exporter.py"]
