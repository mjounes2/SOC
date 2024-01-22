#!/bin/bash

# ANSI escape codes for colors
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg


# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# install Docker 
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y


# Create Docker volume for Portainer data
docker volume create portainer_data

# Copy local folder to Docker volume location
sudo cp -r ./portainer_data /var/lib/docker/volumes

# Run Portainer container
docker run -d -p 9443:9443 --name=portainer --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce \
  --logo "https://raw.githubusercontent.com/mjounes2/SOC/SEIM/VVMlogo.png"

# Add docker User

sudo usermod -aG docker $USER

sysctl -w vm.max_map_count=262144

# confirm installtion 

echo -e "${BLUE}Portainer is now running on port 9443 ${RED}please login using this url (https://<your_local_host_ip>:9443)
                                                            User Name : "soc@vaporvm.com" 
                                                            password : "Pa$$w0rd_2020_VVM" ${NC}.${BLUE}"

sudo docker version

# Function to reset text color to default
reset_color() {
  echo -e "${NC}"
}

reset_color
