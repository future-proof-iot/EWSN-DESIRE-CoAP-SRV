#!/bin/bash
#
# author <Roudy Dagher roudy.dagher@inria.fr>

echo '>>> Mapping v1 for influxql compat'

bucket_id=$(influx bucket find -n $DOCKER_INFLUXDB_INIT_BUCKET --hide-headers | awk '{print $1}')
org_id=$(influx bucket find -n $DOCKER_INFLUXDB_INIT_BUCKET --hide-headers | awk '{print $5}')

echo "bucket_id=$bucket_id"
echo "org_id=$org_id"

influx v1 dbrp create \
  --bucket-id ${bucket_id} \
  --db ${V1_DB_NAME} \
  --rp ${V1_RP_NAME} \
  --org-id ${org_id}

echo '>>> Setting up auth'
influx v1 auth create \
  --username ${V1_AUTH_USERNAME} \
  --password ${V1_AUTH_PASSWORD} \
  --write-bucket ${bucket_id} \
  --org-id ${org_id}
