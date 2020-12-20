#!/bin/bash

mkdir system

scripts/create_ca_cert.sh
scripts/create_server_cert.sh

scripts/handler-sandbox.sh
scripts/mail-sandbox.sh
scripts/client_certs-sandbox.sh
scripts/password-sandbox.sh

scripts/client.sh
