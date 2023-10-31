FROM ubuntu:22.04
RUN apt-get update && apt-get install -y build-essential \
                                        python3.11 \
                                        python3.11-dev \
                                        python3-pip \
                                        wireguard \
                                        iproute2 \
                                        openresolv \
                                        nmap \
                                        && \
                                        python3.11 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3.11 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3.11", "/app/agent/nmap_agent.py"]
