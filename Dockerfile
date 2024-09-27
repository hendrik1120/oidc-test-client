FROM ubuntu:latest
LABEL authors="hendriksievers"

ENTRYPOINT ["top", "-b"]