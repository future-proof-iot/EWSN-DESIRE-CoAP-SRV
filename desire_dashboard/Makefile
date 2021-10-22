# Handy makefile as reminder of docker/docker-compose ops
DOCKER_COMPOSE ?= UUID=$(shell id -u) GID=$(shell id -g) PROV_NODES="${PROV_NODES}" CREDENTIALS_FOLDER_PATH=${CREDENTIALS_FOLDER_PATH} docker-compose
THIS_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
COAP_SRV_PATH = ${THIS_DIR}/../desire_coap_server

PROV_NODES ?= DWE549 DWDB44 DWFF6E
CREDENTIALS_FOLDER_PATH ?= "${HOME}/.pepper"

build:
	@echo 'Building and pulling images'
	${DOCKER_COMPOSE} pull
	${DOCKER_COMPOSE} ${DOCKER_WORKDIR} build 

up:
	@echo 'Powering up the containers'
	echo '' > volumes/telegraf/metrics.out
	${DOCKER_COMPOSE} up -d


down:
	@echo 'Powering down the containers'
	${DOCKER_COMPOSE} down --volumes
	rm -f volumes/telegraf/metrics.out

status:
	@echo 'Docker compose status:'
	${DOCKER_COMPOSE} ps

config:
	@echo 'Docker compose config:'
	${DOCKER_COMPOSE} config


clean: down
	@echo 'Pruning up'
	docker system prune -f

reset_db: clean
	@echo 'reset influxdb'
	rm -rf volumes/influxdb/config/* volumes/influxdb/data/*

launch_coap_server:
	@echo "Laucnhining coap server with nodes = ${PROV_NODES} Press Ctrl+C to exit"
	PYTHONPATH=${COAP_SRV_PATH} python ${COAP_SRV_PATH}/desire_coap_srv.py --host=127.0.0.1 --node-uid ${PROV_NODES} --event-log http://localhost:8080/telegraf

clean_launch: reset_db up
	@echo 'All docker services up'

gen_keys:
	PYTHONPATH=${COAP_SRV_PATH} python ${COAP_SRV_PATH}/tools/edhoc_generate_keys.py
