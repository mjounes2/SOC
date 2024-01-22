#!/bin/bash

# Install Docker
sudo apt-get update
sudo apt-get install -y docker.io

# Create Docker volume for Portainer data
docker volume create portainer_data

# Run Portainer container
docker run -d -p 9443:9443 --name=portainer --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce \
  --logo "https://raw.githubusercontent.com/mjounes2/SOC/SEIM/VVMlogo.png"

echo "Portainer is now running on port 9443."
