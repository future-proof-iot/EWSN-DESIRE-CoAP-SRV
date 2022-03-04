# Handy makefile as reminder of docker/docker-compose ops
DOCKER_COMPOSE ?= UUID=$(shell id -u) GID=$(shell id -g) PROV_NODES="${PROV_NODES}" CREDENTIALS_FOLDER_PATH=${CREDENTIALS_FOLDER_PATH} USE_EDHOC=${USE_EDHOC} docker-compose
THIS_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
COAP_SRV_PATH = ${THIS_DIR}/../desire_coap_server

PROV_NODES ?= DWE549 DWDB44 DWFF6E
CREDENTIALS_FOLDER_PATH ?= "${THIS_DIR}/volumes/coap_srv/pepper_edhoc_creds"

COAP_SERVER_PROFILE=coaps-srv 

build:
	@echo 'Building and pulling images'
	${DOCKER_COMPOSE} pull
	COMPOSE_PROFILES=${COAP_SERVER_PROFILE} ${DOCKER_COMPOSE} build 

up:
	@echo 'Powering up the containers'
	${DOCKER_COMPOSE} up -d

down:
	@echo 'Powering down the containers'
	${DOCKER_COMPOSE} down --volumes

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

USE_EDHOC = --no-edhoc
ifeq ($(USE_EDHOC),yes)
USE_EDHOC = --edhoc
endif
launch_coap_server:
	@echo "Laucnhing coap server with nodes = ${PROV_NODES} Press Ctrl+C to exit"
	${DOCKER_COMPOSE} run --rm --name "coap_srv" coap_srv ${USE_EDHOC} --node-uid ${PROV_NODES} --event-log http://telegraf:8080/telegraf

clean_launch: reset_db up
	@echo 'All docker services up'

gen_keys:
	${DOCKER_COMPOSE} run --no-deps --entrypoint "python tools/edhoc_generate_keys.py" coap_srv
