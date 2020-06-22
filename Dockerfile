FROM python:3.7.0 as build
WORKDIR /semf
COPY ./ ./
RUN \
    mkdir -p /data/uwsgi && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    pip install -r requirements.txt \
    -i http://mirrors.aliyun.com/pypi/simple/ \
    --trusted-host mirrors.aliyun.com && \
