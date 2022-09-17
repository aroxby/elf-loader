FROM ubuntu:jammy

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get -y install build-essential

WORKDIR app
COPY . /app
RUN make all example-lib
CMD ./elf-loader ./example-lib.so example_function
