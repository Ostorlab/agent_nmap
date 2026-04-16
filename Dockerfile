FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y software-properties-common  \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get remove -y python*

RUN apt-get update && apt-get install -y build-essential \
    python3.14 \
    python3.14-dev \
    python3.14-venv \
    wireguard \
    iproute2 \
    openresolv

RUN python3.14 -m ensurepip --upgrade \
    && python3.14 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3.14 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app

FROM base AS builder

WORKDIR /tmp

ARG NMAP_VERSION=7.95

RUN apt-get update && apt-get install -y \
    wget \
    automake \
    python3.14-venv \
    python3-setuptools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3.14 -m pip install build

RUN wget https://nmap.org/dist/nmap-${NMAP_VERSION}.tar.bz2 \
    && tar jxvf nmap-${NMAP_VERSION}.tar.bz2 \
    && cd /tmp/nmap-${NMAP_VERSION} \
    && ./configure --without-zenmap \
    && make \
    && make install \
    && cd / \
    && rm -rf /tmp/nmap-${NMAP_VERSION}

FROM base

COPY --from=builder /usr/local /usr/local

COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app

CMD ["python3.14", "/app/agent/nmap_agent.py"]
