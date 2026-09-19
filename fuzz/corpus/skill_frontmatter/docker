---
name: docker
description: Docker container management
disable-model-invocation: true
metadata:
  wirken:
    requires:
      bins: [docker]
permissions:
  tools:
    allow: [exec]
  egress:
    mode: deny
  inference:
    allow: ["*"]
---

# Docker

Manage Docker containers and images.

## Containers

- List running: `docker ps`
- List all: `docker ps -a`
- Run: `docker run -d --name <name> <image>`
- Stop: `docker stop <name>`
- Remove: `docker rm <name>`
- Logs: `docker logs <name> --tail 50`
- Exec into: `docker exec -it <name> sh`
- Inspect: `docker inspect <name> | jq '.[0].State'`

## Images

- List: `docker images`
- Pull: `docker pull <image>`
- Build: `docker build -t <tag> .`
- Remove: `docker rmi <image>`

## Compose

- Start: `docker compose up -d`
- Stop: `docker compose down`
- Logs: `docker compose logs --tail 50`
- Status: `docker compose ps`

## Cleanup

- Remove stopped containers: `docker container prune -f`
- Remove unused images: `docker image prune -f`
- Disk usage: `docker system df`
