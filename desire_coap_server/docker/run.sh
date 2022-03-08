#!/bin/bash

: "${COAP_HOST:=::}"
: "${COAP_PORT:=5683}"
: "${EDHOC:=--no-edhoc}"
: "${EVENT_LOG:=http://telegraf:8080/telegraf}"
: "${PROV_NODES:=}"

desire-coap-server --node-uid ${PROV_NODES} --host="${COAP_HOST}" --port="${COAP_PORT}" \
                   --event-log="${EVENT_LOG}" ${EDHOC} --loglevel debug
