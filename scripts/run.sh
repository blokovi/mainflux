#!/bin/bash
# Copyright (c) Mainflux
# SPDX-License-Identifier: Apache-2.0

###
# Runs all Mainflux microservices (must be previously built and installed).
#
# Expects that PostgreSQL and needed messaging DB are alredy running.
# Additionally, MQTT microservice demands that Redis is up and running.
#
###

BUILD_DIR=../build

# Kill all mainflux-* stuff
function cleanup {
    pkill mainflux
    pkill nats
}

###
# NATS
###
gnatsd &
counter=1
until nc -zv localhost 4222 1>/dev/null 2>&1;
do
    sleep 0.5
    ((counter++))
    if [ ${counter} -gt 10 ]
    then
        echo -ne "gnatsd failed to start in 5 sec, exiting"
        exit 1
    fi
    echo -ne "Waiting for gnatsd"
done

###
# Users
###
MF_USERS_LOG_LEVEL=info MF_EMAIL_TEMPLATE=../docker/users/emailer/templates/email.tmpl $BUILD_DIR/mainflux-users &

###
# Things
###
MF_THINGS_LOG_LEVEL=info MF_THINGS_HTTP_PORT=8182 MF_THINGS_AUTH_GRPC_PORT=8183 MF_THINGS_AUTH_HTTP_PORT=8989 $BUILD_DIR/mainflux-things &

###
# HTTP
###
MF_HTTP_ADAPTER_LOG_LEVEL=info MF_HTTP_ADAPTER_PORT=8185 MF_THINGS_AUTH_GRPC_URL=localhost:8183 $BUILD_DIR/mainflux-http &

###
# MQTT
###
MF_MQTT_ADAPTER_LOG_LEVEL=info MF_THINGS_AUTH_GRPC_URL=localhost:8183  MF_MQTT_ADAPTER_MQTT_PORT=1884 $BUILD_DIR/mainflux-mqtt &

###
# CoAP
###
MF_COAP_ADAPTER_LOG_LEVEL=info MF_COAP_ADAPTER_PORT=5683 MF_THINGS_AUTH_GRPC_URL=localhost:8183 $BUILD_DIR/mainflux-coap &

###
# AUTHN
###
MF_AUTHN_LOG_LEVEL=debug MF_AUTHN_HTTP_PORT=8189 MF_AUTHN_GRPC_PORT=8181 MF_AUTHN_DB_PORT=5432 MF_AUTHN_DB_USER=mainflux MF_AUTHN_DB_PASS=mainflux MF_AUTHN_DB=authn MF_AUTHN_SECRET=secret $BUILD_DIR/mainflux-authn &

###
# Writer
###
MF_POSTGRES_WRITER_LOG_LEVEL=debug MF_POSTGRES_WRITER_SUBJECTS_CONFIG=subjects.toml MF_POSTGRES_WRITER_DB_HOST=localhost MF_POSTGRES_WRITER_DB_PORT=5432 MF_POSTGRES_WRITER_PORT=9104 $BUILD_DIR/mainflux-postgres-writer &

###
# Reader
###
MF_THINGS_AUTH_GRPC_URL=localhost:8183 MF_POSTGRES_READER_LOG_LEVEL=debug MF_POSTGRES_READER_PORT=9204 MF_POSTGRES_READER_CLIENT_TLS=false MF_POSTGRES_READER_CA_CERTS="" MF_POSTGRES_READER_DB_PORT=5432 MF_POSTGRES_READER_DB_USER=mainflux MF_POSTGRES_READER_DB_PASS=mainflux MF_POSTGRES_READER_DB=messages MF_POSTGRES_READER_DB_SSL_MODE=disable MF_POSTGRES_READER_DB_SSL_CERT="" MF_POSTGRES_READER_DB_SSL_KEY="" MF_POSTGRES_READER_DB_SSL_ROOT_CERT="" $BUILD_DIR/mainflux-postgres-reader &


trap cleanup EXIT

while : ; do sleep 1 ; done
