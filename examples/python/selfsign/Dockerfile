FROM ubuntu:18.04

RUN apt-get update -y && apt-get install -y \
  openssl

COPY ./selfsign.sh /selfsign.sh
RUN ["chmod", "+x", "/selfsign.sh"]
ENTRYPOINT [ "/selfsign.sh" ]
