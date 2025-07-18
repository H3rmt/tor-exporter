FROM python:alpine@sha256:37b14db89f587f9eaa890e4a442a3fe55db452b69cca1403cc730bd0fbdc8aaf
RUN pip install stem prometheus_client retrying

COPY ./prometheus-tor-exporter.py /prometheus-tor-exporter.py
ENTRYPOINT ["/usr/local/bin/python", "/prometheus-tor-exporter.py"]
