#! /bin/bash

uwsgi --ini ./uwsgi.ini &
python -m celery -A SeMF worker -l info &
