#!/bin/bash
openssl req -newkey rsa:4096 -nodes -keyout server_key.pem -x509 -days 365 -out server_cert.pem
openssl req -newkey rsa:2048 -nodes -keyout client_key.pem -x509 -days 365 -out client_cert.pem
