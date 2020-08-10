#! /bin/bash

uwsgi --ini ./uwsgi.ini &
python -m celery -A SeMF worker -l info &
python -m celery -A SeMF beat -l info
