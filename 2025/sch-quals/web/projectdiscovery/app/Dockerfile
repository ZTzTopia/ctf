FROM python:3.10

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y \
    pkg-config \
    gcc \
    unzip \
    curl

RUN useradd -m ctf

RUN wget "https://github.com/projectdiscovery/nuclei/releases/download/v3.4.10/nuclei_3.4.10_linux_amd64.zip"
RUN unzip nuclei_3.4.10_linux_amd64.zip
RUN rm nuclei_3.4.10_linux_amd64.zip
RUN mv nuclei /usr/local/bin

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

ENV PG_HOST=db \
    PG_USER=postgres \
    PG_PASSWORD=postgres \
    PG_DB=postgres

USER ctf

EXPOSE 1337

CMD ["python3", "main.py"]
