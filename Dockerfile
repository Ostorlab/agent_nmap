FROM python:3.8-alpine as base
FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt
FROM base
COPY --from=builder /install /usr/local
COPY src /app
WORKDIR /app
CMD ["python3", "agent.py"]