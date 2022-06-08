# Contact Tracing Dashboard

The dashboard consists on a `telegraf` + `influxdb` + `grafana` stack that can subscribe to events logged by the CoAP contact tracing server to display nodes:

- infection status
- exposure status
- average observed distance between nodes (if in critical distance)
- logged pets
- etc.

## Requirements

- `docker` installed and current user in `docker` group if you want ot avoid running as `root`
- `docker-compose` installed

## Setup

A Docker-Compose is provided to setup the `telegraf` + `influxdb` + `grafana` stack.
A couple environment variables need to be set, this can be done through a `.env ` file:

```bash
# .env
UID=1000
GID=1000
```

or through shell environment variables:

```bash
$ export UID=$(id -u)
$ export GID=$(id -g)
$ docker-compose up
```

Env Variables:

- UID: user id, e.g.: `$ id -g`
- GID: user group id, e.g.: `$ id -u`

### Optional profiles

`'coaps-srv'` profile:

A couple of extra variables need to be setup for this profile, this can be done
in the same `.env` file:

```bash
# .env
UID=1000
GID=1000
DOCKER_REGISTRY=inriapepper
PROV_NODES="DW1234 DWABCD"
COAP_HOST="fd00:dead:beef::1"
COAP_PORT="5683"
EVENT_LOG="http://127.0.0.1:8080/telegraf"
UUID=1000
GID=1000
CREDENTIALS_FOLDER_PATH=$HOME/.pepper
```

Env Variables:

- DOCKER_REGISTRY: registry to pull the `desire-coap-server` image
- COAP_HOST: address to bind the CoAP server to, e.g.: "fd00:dead:beef::1"
- COAP_PORT: port to bind the CoAP server to, e.g.: 5683
- EVENT_LOG: URI where the CoAP server will post events, e.g.: http://127.0.0.1:8080/telegraf
- PROV_NODES: list of nodes ids, e.g.: `DW1234`
- CREDENTIALS_FOLDER_PATH: path with the registered nodes credentials, e.g.: $HOME/.pepper

## Usage

1. Start the `telegraf` + `influxdb` + `grafana` stack

```bash
$ docker-compose up
```

or with the `coaps-srv`

```bash
$ docker-compose --profile coaps-srv up
```

to daemonize add `-d`

1. Verify that all is up and running

```bash
$ docker-compose ps
Docker compose status:
  Name             Command           State                                   Ports
-------------------------------------------------------------------------------------------------------------------
grafana    /run.sh                   Up      0.0.0.0:3000->3000/tcp,:::3000->3000/tcp
influxdb   /entrypoint.sh influxd    Up      0.0.0.0:8086->8086/tcp,:::8086->8086/tcp
telegraf   /entrypoint.sh telegraf   Up      0.0.0.0:8080->8080/tcp,:::8080->8080/tcp, 8092/udp, 8094/tcp, 8125/udp
```

1. If not using the `coaps-srv` profile then start the server, see [here](../desire_coap_server/README.md) for details.

1. Check that the influxdb database has been initialized with an event triplet `(DW1234, DWABCD)` per provisioned node)
```bash
$ cat volumes/telegraf/log/metrics.out
infection,host=telegraf,node_id=DW1234 infected=false 1632857590230054864
exposure,host=telegraf,node_id=DW1234 contact=false 1632857590256665508
status,host=telegraf,node_id=DW1234 value="ok" 1632857590270714826
infection,host=telegraf,node_id=DWABCD infected=false 1632857590279903850
exposure,host=telegraf,node_id=DWABCD contact=false 1632857590292380514
status,host=telegraf,node_id=DWABCD value="ok" 1632857590308895019
```

1. Open the grafana dashboard on this link [http://localhost:3000/d/SG9hNcNnk/pepper-riot-fp-viz?orgId=1&refresh=1s](http://localhost:3000/d/SG9hNcNnk/pepper-riot-fp-viz?orgId=1&refresh=1s):
    - user: `admin`
    - pass: `pepper`


1. To stop the stack

```bash
$ docker-compose down
```

1. To reset the database

```bash
$ docker volume rm influxdb-data
$ docker volume rm influxdb-config
```
