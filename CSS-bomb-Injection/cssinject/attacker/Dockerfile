FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Added --break-system-packages to bypass PEP 668 restriction in modern Ubuntu
RUN pip3 install --no-cache-dir --break-system-packages flask

COPY . /app

EXPOSE 5000

CMD ["python3", "app.py"]
