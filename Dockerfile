FROM  ubuntu:22.04 as base
FROM base as builder
RUN apt-get update &&  apt-get install -y build-essential python3-pip python3.10 wireguard iproute2 openresolv
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
RUN apt-get update && apt-get install -y nmap
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/nmap_agent.py"]
