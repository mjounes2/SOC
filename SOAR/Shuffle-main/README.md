<h1 align="center">

[![Shuffle Logo](https://github.com/Shuffle/Shuffle/blob/main/frontend/public/images/Shuffle_logo_new.png)](https://shuffler.io)

Shuffle Automation

[![CodeQL](https://github.com/Shuffle/Shuffle/actions/workflows/codeql-analysis.yml/badge.svg?branch=launch)](https://github.com/Shuffle/Shuffle/actions/workflows/codeql-analysis.yml)
[![Autobuild](https://github.com/Shuffle/Shuffle/actions/workflows/dockerbuild.yaml/badge.svg?branch=launch)](https://github.com/Shuffle/Shuffle/actions/workflows/dockerbuild.yaml)

</h1><h4 align="center">

[Shuffle](https://shuffler.io) is an automation platform for and by the community, focusing on accessibility for anyone to automate. Security operations is complex, but it doesn't have to be.

</h4>

![Example Shuffle webhook integration](https://github.com/frikky/Shuffle/blob/main/frontend/src/assets/img/github_shuffle_img.png)


<h1 align="center">

[![Shuffle Logo](https://github.com/Shuffle/Shuffle/blob/main/frontend/public/images/Shuffle_logo_new.png)](https://shuffler.io)

Shuffle Installation

</h1>

Installation of Shuffle is currently available for docker and kubernetes. Looking for how to update Shuffle? Check the [updating guide](https://shuffler.io/docs/configuration#updating_shuffle)

This document outlines an introduction environment which is not scalable. [Read here](https://shuffler.io/docs/configuration#production_readiness) for information on production readiness. This also includes system requirements and configurations for Swarm or Kubernetes. 

# Docker - *nix
The Docker setup is done with docker-compose 

**PS: if you're setting up Shuffle on Windows, go to the next step (Windows Docker setup)**

1. Make sure you have [Docker](https://docs.docker.com/get-docker/) and [docker-compose](https://docs.docker.com/compose/install/) installed, and that you have a minimum of **2Gb of RAM** available.
2. Download Shuffle
```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
```

3. Fix prerequisites for the Opensearch database (Elasticsearch): 
```bash
mkdir shuffle-database                    # Create a database folder
sudo chown -R 1000:1000 shuffle-database  # IF you get an error using 'chown', add the user first with 'sudo useradd opensearch'

sudo swapoff -a                           # Disable swap
```

4. Run docker-compose.
```bash
docker-compose up -d
```

5. Recommended for Opensearch to work well
```bash
sudo sysctl -w vm.max_map_count=262144             # https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html
```

When you're done, skip to the [After installation](#after-installation) step below.


### Configurations (high availability, scale, proxies, default users etc.)
https://shuffler.io/docs/configuration

![architecture](https://github.com/frikky/Shuffle/raw/main/frontend/src/assets/img/shuffle_architecture.png)

### After installation 
1. After installation, go to http://localhost:3001 (or your servername - https is on port 3443)
2. Now set up your admin account (username & password). Shuffle doesn't have a default username and password. 
3. Sign in with the same Username & Password! Go to /apps and see if you have any apps yet. If not - you may need to [configure proxies](https://shuffler.io/docs/configuration#production_readiness)
4. Check out https://shuffler.io/docs/configuration as it has a lot of useful information to get started

![Admin account setup](https://github.com/Shuffle/Shuffle/blob/main/frontend/src/assets/img/shuffle_adminaccount.png?raw=true)

### Useful info
* Check out [getting started](https://shuffler.io/docs/getting_started)
* The default state of Shuffle is NOT scalable. See [production setup](https://shuffler.io/docs/configuration#production_readiness) for more info
* The server is available on http://localhost:3001 (or your servername)
* Further configurations can be done in docker-compose.yml and .env.
* Default database location is in the same folder: ./shuffle-database

# Local development installation

Local development is pretty straight forward with **ReactJS** and **Golang**. This part is intended to help you run the code for development purposes. We recommend having Shuffle running with the Docker-compose, then manually running the portion that you want to test and/or edit.

**PS: You have to stop the Backend Docker container to get this one working**

**PPS: Use the "main" branch when developing to get it set up easier**

## Frontend - ReactJS /w cytoscape
http://localhost:3000 - Requires [npm](https://nodejs.org/en/download/)/[yarn](https://yarnpkg.com/lang/en/docs/install/#debian-stable)/your preferred manager. Runs independently from backend.
```bash
cd frontend
yarn install
yarn start
```

## Backend - Golang
http://localhost:5001 - REST API - requires [>=go1.13](https://golang.org/dl/)
```bash
export SHUFFLE_OPENSEARCH_URL="https://localhost:9200"
export SHUFFLE_ELASTIC=true
export SHUFFLE_OPENSEARCH_USERNAME=admin
export SHUFFLE_OPENSEARCH_PASSWORD=admin
export SHUFFLE_OPENSEARCH_SKIPSSL_VERIFY=true
cd backend/go-app
go run main.go walkoff.go docker.go
```

## Database - Opensearch 
Make sure this is running through the docker-compose, and that the backend points to it with SHUFFLE_OPENSEARCH_URL defined.

So essentially, what that means is:
1. Make sure you have docker-compose installed
2. Make sure you have the docker-compose.yml file from this repository
3. Run `docker-compose up opensearch -d`

## Orborus
Execution of Workflows:
PS: This requires some specific environment variables
```
cd functions/onprem/orborus
go run orborus.go
```

Environments (modify for Windows):
```
export ORG_ID=Shuffle
export ENVIRONMENT_NAME=Shuffle
export BASE_URL=http://YOUR-IP:5001
export DOCKER_API_VERSION=1.40
```

AND THAT's it - hopefully, it worked. If it didn't please email [SOC@Vaporvm.com](mailto:soc@vaporvm.com)


