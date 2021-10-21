Temporary steps:
==
Requirements:
- docker installed and current user in `docker` group if you want ot avoid running as `root`
- docker-compose installed

Follow the below steps

1. Pull docker images
```shell
$ make build
```
2. Start the stack: Telegraf, influxdb and grafana
```shell
$ make up
```
3. Check services are up
```shell
$ make status
Docker compose status:
UUID=1000 GID=1000 docker-compose ps
  Name             Command           State                                   Ports                                 
-------------------------------------------------------------------------------------------------------------------
grafana    /run.sh                   Up      0.0.0.0:3000->3000/tcp,:::3000->3000/tcp                              
influxdb   /entrypoint.sh influxd    Up      0.0.0.0:8086->8086/tcp,:::8086->8086/tcp                              
telegraf   /entrypoint.sh telegraf   Up      0.0.0.0:8080->8080/tcp,:::8080->8080/tcp, 8092/udp, 8094/tcp, 8125/udp
```
4. Run the coap server with list of enrolled devices from the env variable `${PROV_NODES}`. This should be run in a dedicated terminal (blocking)
```shell
$ PROV_NODES="DWE549 DWDB44 DWFF6E" make launch_coap_server 
```

5. Check that the influxdb database has been initialized with an event triplet `(DWE549, DWDB44, DWFF6E)` per provisioned node
```shell
$ cat volumes/telegraf/metrics.out 

infection,host=telegraf,node_id=DWE549 infected=false 1632857590230054864
exposure,host=telegraf,node_id=DWE549 contact=false 1632857590256665508
status,host=telegraf,node_id=DWE549 value="ok" 1632857590270714826
infection,host=telegraf,node_id=DWDB44 infected=false 1632857590279903850
exposure,host=telegraf,node_id=DWDB44 contact=false 1632857590292380514
status,host=telegraf,node_id=DWDB44 value="ok" 1632857590308895019
infection,host=telegraf,node_id=DWFF6E infected=false 1632857590331656695
exposure,host=telegraf,node_id=DWFF6E contact=false 1632857590334580839
status,host=telegraf,node_id=DWFF6E value="ok" 1632857590341673299  
```

6. Open the grafana dashboard on this link [http://localhost:3000/d/SG9hNcNnk/pepper-riot-fp-viz?orgId=1&refresh=1s](http://localhost:3000/d/SG9hNcNnk/pepper-riot-fp-viz?orgId=1&refresh=1s):
    - user: `admin`
    - pass: `pepper`

**Notes**
1. Resetting the database
```shell
$ make reset_db
```
2. A clean start: this will stop the stack, clean the database and restart the stack and the coap server
```shell
$ PROV_NODES="DWE549 DWDB44 DWFF6E" make clean_launch 
```