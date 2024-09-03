FROM ubuntu:22.04

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

WORKDIR /tmp

RUN apt-get install wget
RUN wget https://nmap.org/dist/nmap-7.95.tar.bz2

RUN tar jxvf nmap-7.95.tar.bz2

WORKDIR /tmp/nmap-7.95

RUN python3 -m pip install build
RUN apt install python3.10-venv -y
RUN apt-get install automake -y
RUN ./configure && make && sudo make install

WORKDIR /
RUN rm -rf /tmp/nmap-7.95


RUN python3.11 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3.11 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/nmap_agent.py"]
