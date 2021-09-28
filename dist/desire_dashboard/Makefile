# Handy makefile as reminder of docker/docker-compose ops

DOCKER_COMPOSE?=UUID=$(shell id -u) GID=$(shell id -g) docker-compose

build:
	@echo 'Building and pulling images'
	${DOCKER_COMPOSE} ${DOCKER_WORKDIR} build
	${DOCKER_COMPOSE} pull

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

THIS_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
COAP_SRV_PATH=${THIS_DIR}/../desire_coap_server
PROV_NODES?=DWE549 DWDB44 DWFF6E

launch_coap_server:
	@echo "Laucnhining coap server with nodes = ${PROV_NODES} Press Ctrl+C to exit"
	PYTHONPATH=${COAP_SRV_PATH} python ${COAP_SRV_PATH}/desire_coap_srv.py --node-uid ${PROV_NODES} --no-test

clean_launch: reset_db up launch_coap_server
	@echo 'You will never see this message'