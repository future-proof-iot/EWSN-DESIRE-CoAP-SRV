# Handy makefile as reminder of docker/docker-compose ops

DOCKER_COMPOSE?=UUID=$(shell id -u) GID=$(shell id -g) docker-compose

build:
	@echo 'Building and pulling images'
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
	docker system prune
