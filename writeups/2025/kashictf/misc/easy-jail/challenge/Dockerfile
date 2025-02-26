FROM python:3.12-slim

WORKDIR /challenge

COPY chall.py /challenge/chall.py
COPY flag.txt /flag.txt

RUN chmod +x /challenge/chall.py


CMD ["python", "/challenge/chall.py"]
