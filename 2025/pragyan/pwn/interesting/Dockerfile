FROM ubuntu@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97
## Ubuntu 22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update --fix-missing && apt-get -y upgrade
RUN apt-get install -y socat

RUN useradd -m pctf

COPY challenge/chal challenge/flag.txt /pctf/

RUN chown -R pctf:pctf /pctf/

WORKDIR /pctf

USER pctf

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,fork", "EXEC:./chal"]