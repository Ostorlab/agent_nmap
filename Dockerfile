FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y software-properties-common  \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get remove -y python*

RUN apt-get update && apt-get install -y build-essential \
    python3.11 \
    python3.11-dev \
    python3-pip \
    wireguard \
    iproute2 \
    openresolv

RUN python3.11 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3.11 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app

FROM base AS builder

WORKDIR /tmp

ARG NMAP_VERSION=7.95

RUN apt-get update && apt-get install -y \
    wget \
    automake \
    python3-venv \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install build

RUN wget https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2 \
    && tar jxvf nmap-${NMAP_VERSION}.tar.bz2 \
    && cd /tmp/nmap-${NMAP_VERSION} \
    && ./configure \
    && make \
    && sudo make install \
    && cd / \
    && rm -rf /tmp/nmap-$(NMAP_VERSION)

FROM base

COPY --from=builder /usr/local /usr/local

CMD ["python3.11", "/app/agent/nmap_agent.py"]
