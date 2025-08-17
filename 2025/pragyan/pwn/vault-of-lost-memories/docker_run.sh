#!/bin/sh
docker build --tag=vault .
docker run -it -p 9009:1337 --rm --name=vault vault