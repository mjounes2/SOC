# Wazuh containers for Docker

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

In this repository you will find the containers to run:

* Wazuh manager: it runs the Wazuh manager, Wazuh API and Filebeat OSS
* Wazuh dashboard: provides a web user interface to browse through alert data and allows you to visualize the agents configuration and status.
* Wazuh indexer: Wazuh indexer container (working as a single-node cluster or as a multi-node cluster). **Be aware to increase the `vm.max_map_count` setting, as it's detailed in the [Wazuh documentation](https://documentation.wazuh.com/current/docker/wazuh-container.html#increase-max-map-count-on-your-host-linux).**

The folder `build-docker-images` contains a README explaining how to build the Wazuh images and the necessary assets.
The folder `indexer-certs-creator` contains a README explaining how to create the certificates creator tool and the necessary assets.
The folder `multi-node` contains a README explaining how to run a Wazuh environment with two Wazuh managers, three Wazuh indexers, and one Wazuh dashboard.

## Documentation

* [Wazuh full documentation](http://documentation.wazuh.com)
* [Wazuh documentation for Docker](https://documentation.wazuh.com/current/docker/index.html)
* [Docker Hub](https://hub.docker.com/u/wazuh)


### Setup SSL certificate

Before starting the environment it is required to provide an SSL certificate (or just generate one self-signed).

Documentation on how to provide these two can be found at [Wazuh Docker Documentation](https://documentation.wazuh.com/current/docker/wazuh-container.html#production-deployment).


## Environment Variables

Default values are included when available.

### Wazuh
```
API_USERNAME="wazuh-wui"                            # Wazuh API username
API_PASSWORD="MyS3cr37P450r.*-"                     # Wazuh API password - Must comply with requirements
                                                    # (8+ length, uppercase, lowercase, special chars)

INDEXER_URL=https://wazuh.indexer:9200              # Wazuh indexer URL
INDEXER_USERNAME=admin                              # Wazuh indexer Username
INDEXER_PASSWORD=SecretPassword                     # Wazuh indexer Password
FILEBEAT_SSL_VERIFICATION_MODE=full                 # Filebeat SSL Verification mode (full or none)
SSL_CERTIFICATE_AUTHORITIES=""                      # Path of Filebeat SSL CA
SSL_CERTIFICATE=""                                  # Path of Filebeat SSL Certificate
SSL_KEY=""                                          # Path of Filebeat SSL Key
```

### Dashboard
```
PATTERN="wazuh-alerts-*"        # Default index pattern to use

CHECKS_PATTERN=true             # Defines which checks must be considered by the healthcheck
CHECKS_TEMPLATE=true            # step once the Wazuh app starts. Values must be true or false
CHECKS_API=true
CHECKS_SETUP=true

EXTENSIONS_PCI=true             # Enable PCI Extension
EXTENSIONS_GDPR=true            # Enable GDPR Extension
EXTENSIONS_HIPAA=true           # Enable HIPAA Extension
EXTENSIONS_NIST=true            # Enable NIST Extension
EXTENSIONS_TSC=true             # Enable TSC Extension
EXTENSIONS_AUDIT=true           # Enable Audit Extension
EXTENSIONS_OSCAP=false          # Enable OpenSCAP Extension
EXTENSIONS_CISCAT=false         # Enable CISCAT Extension
EXTENSIONS_AWS=false            # Enable AWS Extension
EXTENSIONS_GCP=false            # Enable GCP Extension
EXTENSIONS_VIRUSTOTAL=false     # Enable Virustotal Extension
EXTENSIONS_OSQUERY=false        # Enable OSQuery Extension
EXTENSIONS_DOCKER=false         # Enable Docker Extension

APP_TIMEOUT=20000               # Defines maximum timeout to be used on the Wazuh app requests

API_SELECTOR=true               Defines if the user is allowed to change the selected API directly from the Wazuh app top menu
IP_SELECTOR=true                # Defines if the user is allowed to change the selected index pattern directly from the Wazuh app top menu
IP_IGNORE="[]"                  # List of index patterns to be ignored

DASHBOARD_USERNAME=kibanaserver     # Custom user saved in the dashboard keystore
DASHBOARD_PASSWORD=kibanaserver     # Custom password saved in the dashboard keystore
WAZUH_MONITORING_ENABLED=true       # Custom settings to enable/disable wazuh-monitoring indices
WAZUH_MONITORING_FREQUENCY=900      # Custom setting to set the frequency for wazuh-monitoring indices cron task
WAZUH_MONITORING_SHARDS=2           # Configure wazuh-monitoring-* indices shards and replicas
WAZUH_MONITORING_REPLICAS=0         ##
```

## Directory structure

    ├── build-docker-images
    │   ├── docker-compose.yml
    │   ├── wazuh-dashboard
    │   │   ├── config
    │   │   │   ├── config.sh
    │   │   │   ├── config.yml
    │   │   │   ├── entrypoint.sh
    │   │   │   ├── opensearch_dashboards.yml
    │   │   │   ├── wazuh_app_config.sh
    │   │   │   └── wazuh.yml
    │   │   └── Dockerfile
    │   ├── wazuh-indexer
    │   │   ├── config
    │   │   │   ├── action_groups.yml
    │   │   │   ├── config.sh
    │   │   │   ├── config.yml
    │   │   │   ├── entrypoint.sh
    │   │   │   ├── internal_users.yml
    │   │   │   ├── opensearch.yml
    │   │   │   ├── roles_mapping.yml
    │   │   │   ├── roles.yml
    │   │   │   └── securityadmin.sh
    │   │   └── Dockerfile
    │   └── wazuh-manager
    │       ├── config
    │       │   ├── create_user.py
    │       │   ├── etc
    │       │   │   ├── cont-init.d
    │       │   │   │   ├── 0-wazuh-init
    │       │   │   │   ├── 1-config-filebeat
    │       │   │   │   └── 2-manager
    │       │   │   └── services.d
    │       │   │       ├── filebeat
    │       │   │       │   ├── finish
    │       │   │       │   └── run
    │       │   │       └── ossec-logs
    │       │   │           └── run
    │       │   ├── filebeat.yml
    │       │   ├── permanent_data.env
    │       │   ├── permanent_data.sh
    │       │   └── wazuh.repo
    │       └── Dockerfile
    ├── CHANGELOG.md
    ├── indexer-certs-creator
    │   ├── config
    │   │   └── entrypoint.sh
    │   └── Dockerfile
    ├── LICENSE
    ├── multi-node
    │   ├── config
    │   │   ├── nginx
    │   │   │   └── nginx.conf
    │   │   ├── wazuh_cluster
    │   │   │   ├── wazuh_manager.conf
    │   │   │   └── wazuh_worker.conf
    │   │   ├── wazuh_dashboard
    │   │   │   ├── opensearch_dashboards.yml
    │   │   │   └── wazuh.yml
    │   │   ├── wazuh_indexer
    │   │   │   ├── internal_users.yml
    │   │   │   ├── wazuh1.indexer.yml
    │   │   │   ├── wazuh2.indexer.yml
    │   │   │   └── wazuh3.indexer.yml
    │   │   └── wazuh_indexer_ssl_certs
    │   │       └── certs.yml
    │   ├── docker-compose.yml
    │   ├── generate-indexer-certs.yml
    │   ├── Migration-to-Wazuh-4.3.md
    │   └── volume-migrator.sh
    ├── README.md
    ├── single-node
    │   ├── config
    │   │   ├── wazuh_cluster
    │   │   │   └── wazuh_manager.conf
    │   │   ├── wazuh_dashboard
    │   │   │   ├── opensearch_dashboards.yml
    │   │   │   └── wazuh.yml
    │   │   ├── wazuh_indexer
    │   │   │   ├── internal_users.yml
    │   │   │   └── wazuh.indexer.yml
    │   │   └── wazuh_indexer_ssl_certs
    │   │       ├── admin-key.pem
    │   │       ├── admin.pem
    │   │       ├── certs.yml
    │   │       ├── root-ca.key
    │   │       ├── root-ca.pem
    │   │       ├── wazuh.dashboard-key.pem
    │   │       ├── wazuh.dashboard.pem
    │   │       ├── wazuh.indexer-key.pem
    │   │       ├── wazuh.indexer.pem
    │   │       ├── wazuh.manager-key.pem
    │   │       └── wazuh.manager.pem
    │   ├── docker-compose.yml
    │   ├── generate-indexer-certs.yml
    │   └── README.md
    └── VERSION




We thank them and everyone else who has contributed to this project.

## License and copyright

Wazuh Docker Copyright (C) 2017, Wazuh Inc. (License GPLv2)

## Web references

[Wazuh website](http://wazuh.com)