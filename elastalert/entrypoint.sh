#!/bin/sh
set -e
python /opt/elastalert/render_config.py
exec elastalert "$@"
