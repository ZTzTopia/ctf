FROM postgres:16

RUN apt-get update && rm -rf /var/lib/apt/lists/*

COPY init.sql /docker-entrypoint-initdb.d/

ENV POSTGRES_USER=3862661a91097ea6c69b086cbb3313d5 \
    POSTGRES_PASSWORD=48b9ace67461ad1903a3c4b4286de6bf \
    POSTGRES_DB=postgres \
    FLAG=SCH25{FAKEFLAG}
