FROM python:3.8-slim-buster

LABEL maintainer="Roudy Dagher <roudy.dagher@inria.fr>" \
      description="Coap Server for pepper riotfp demos"

RUN apt-get update && apt-get install -y git \
    && apt-get autoremove && apt-get autoclean
RUN pip install --upgrade pip

COPY . opt/
RUN cd opt/desire_coap_server && pip install . && cd

ADD /desire_coap_server/docker/run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 5683/udp

CMD ["/run.sh"]
