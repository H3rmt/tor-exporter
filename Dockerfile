FROM python:alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc
RUN pip install stem prometheus_client retrying

COPY ./prometheus-tor-exporter.py /prometheus-tor-exporter.py
ENTRYPOINT ["/usr/local/bin/python", "/prometheus-tor-exporter.py"]
