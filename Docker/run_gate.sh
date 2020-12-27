#!/bin/bash
source ./docker.env
echo "IP address of virtual machine:"
grep -i hostname ../Ansible/ssh_config.cfg

echo "Building image on the remote host"
docker build -t gdg/myproxy:test .

echo "Starting container"
docker run --rm -p 8443:8443 -p 8222:8222 gdg/myproxy:test
