# Docker Integration

This document describes how you can use BPFContain to confine Docker containers.

## Flow

1. Start BPFContain
1. Launch a Docker container
1. Apply a policy to the Docker container
1. Enforce policy rules on the Docker container

## Example policies
Note that implicitly the container receives access to any filesystem it mounts 

```Yaml
name: docker-device

allow:
  - dev: terminal
```

```Yaml
name: docker-server

allow:
  - dev: terminal
  - net: [server, send, recv]
```

## Usage
Launch container
```
docker run -it busybox
```
Get container pid
```
docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED          STATUS          PORTS
7d109859d884   busybox   "sh"      17 seconds ago   Up 16 seconds             
```
```
sudo docker inspect 7d109859d884 --format '{{.State.Pid}}'
15292
```
Apply policy to the container
```
bpfcontain confine 15292 device.yml
```

## Web server example
Launch container
```
docker run -p 9000:9000 -it python bash
```
Get container pid
```
docker ps
CONTAINER ID   IMAGE     COMMAND   PORTS                                      
2034ead7c760   python    "bash"    0.0.0.0:9000->9000/tcp,:::9000->9000/tcp     
```
```
sudo docker inspect 2034ead7c760 --format '{{.State.Pid}}'
21377
```
Apply policy to the container
```
bpfcontain confine 21377 server.yml
```
Start python web server
```
python -m http.server 9000
```

