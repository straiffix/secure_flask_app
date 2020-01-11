#!/bin/sh

export FLASK_APP=Secure_app
export FLASK_DEBUG=1
flask run --cert=Secure_app/certs/server.crt --key=Secure_app/certs/server.key
