FROM python:3.8-slim-buster
LABEL maintainer="Roudy Dagher <roudy.dagher@inria.fr>" \
      description="Coap Server for pepper riotfp demos"

RUN apt-get update && apt-get install -y git && apt-get autoremove && apt-get autoclean
RUN pip install --upgrade pip
ENV PYTHONPATH "${PYTONPATH}:/${PWD}"

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 5683/udp
VOLUME /root/.pepper

ENTRYPOINT ["python", "desire_coap_srv.py", "--host", "127.0.0.1"]