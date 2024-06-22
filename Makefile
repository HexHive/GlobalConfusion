DOCKER := docker
TARGET ?= VNS-L31C432B160_task_storage
TEE ?= optee
TIMEOUT ?= 600

.PHONY: build run help

help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

sh-tipi:
	@$(DOCKER) compose run --rm tipi /bin/bash

run-tipi: ## Run the Docker container(s)
	@$(DOCKER) compose run --rm tipi /tipi-entrypoint.sh ${TARGET} ${TEE} ${TIMEOUT}

test-tipi: ## Run tipi test suite
	@$(DOCKER) compose run --rm tipi /tipi-test-entrypoint.sh
