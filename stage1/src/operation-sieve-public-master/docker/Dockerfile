ARG BASE=ubuntu:22.04
FROM ${BASE} as base
MAINTAINER Clasm

ENV DEBIAN_FRONTEND=noninteractive

USER root
RUN apt-get update && apt-get -y install software-properties-common dirmngr apt-transport-https lsb-release ca-certificates

FROM base as python_build
RUN add-apt-repository ppa:deadsnakes/ppa -y
RUN apt-get update && apt-get -o APT::Immediate-Configure=0 install -y \
    git sudo virtualenvwrapper python3.11-dev python3.11-venv python3-pip build-essential libxml2-dev \
    libxslt1-dev git libffi-dev cmake libreadline-dev libtool debootstrap \
    debian-archive-keyring libglib2.0-dev libpixman-1-dev qtdeclarative5-dev \
    binutils-multiarch nasm libc6 libgcc1 libstdc++6 \
    libtinfo5 zlib1g vim openssl libssl-dev openjdk-8-jdk graphviz graphviz-dev\
    && rm -rf /var/lib/apt/lists/*

FROM python_build as angr_repo

#RUN . /angr/bin/activate && pip install py-spy rich docker toml kubernetes

FROM angr_repo as sieve_repo

RUN mkdir /operation-sieve
COPY . /operation-sieve
RUN cd / && python3.11 -m venv angr
WORKDIR /operation-sieve

RUN touch /operation-sieve/setup.cfg
RUN . /angr/bin/activate && pip install --upgrade pip
RUN . /angr/bin/activate && pip install --no-cache-dir -e .
RUN . /angr/bin/activate && pip install --no-cache-dir -e pipeline
RUN . /angr/bin/activate && pip install --no-cache-dir openai
RUN . /angr/bin/activate && pip install --no-cache-dir 'cffi<2.0' 'pycparser<3.0'
RUN cd /angr/lib/python3.11/site-packages && git apply /operation-sieve/docker/live_def.patch

WORKDIR /operation-sieve
RUN ln -s /angr/bin/sieve /usr/local/bin/sieve
RUN ln -s /angr/bin/env_resolve /usr/local/bin/env_resolve
RUN ln -s /angr/bin/sieve-pipeline /usr/local/bin/sieve-pipeline

COPY ./docker/entrypoint.py /
RUN chmod +x /entrypoint.py
