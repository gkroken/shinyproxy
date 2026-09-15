# Skald — build and dev-stack targets.
# There is no local JDK or Maven; everything Java runs in a container.

MAVEN_IMAGE := maven:3.9-eclipse-temurin-21
COMPOSE     := docker compose -f docker-compose.dev.yml

# The Maven cache lives OUTSIDE the repo on purpose: license-maven-plugin runs with
# <aggregate>true</aggregate> and would otherwise scan every downloaded .pom under it.
M2       := $(HOME)/.cache/skald/m2
M2_HOME  := $(HOME)/.cache/skald/m2home

# HOME=/m2home is required: without it the image fails on `mkdir /root`.
# The cache dirs must exist and be owned by us before the run, or Docker creates them
# root-owned and Maven dies with AccessDeniedException.
MVN := docker run --rm -u $(shell id -u):$(shell id -g) -e HOME=/m2home \
	-v "$(CURDIR)":/ws -v "$(M2)":/m2 -v "$(M2_HOME)":/m2home \
	-w /ws $(MAVEN_IMAGE) mvn -B -Dmaven.repo.local=/m2

.PHONY: build test dev down logs clean shell

build:                        ## Build the executable jar
	@mkdir -p "$(M2)" "$(M2_HOME)"
	$(MVN) -DskipTests package

# Upstream's tests start real containers and then talk to them on published ports.
# That needs two things the plain build container does not have:
#   --network host   so `localhost:<port>` inside the container is the host's localhost
#                    (CI runs Maven on the host, which is why it never needed this)
#   the Docker socket + its group, so the Docker backend can start anything at all
# Without them 13 of 44 tests fail in ways that look like product bugs.
DOCKER_GID := $(shell stat -c '%g' /var/run/docker.sock)
MVN_DOCKER := docker run --rm --network host --group-add $(DOCKER_GID) \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-u $(shell id -u):$(shell id -g) -e HOME=/m2home \
	-v "$(CURDIR)":/ws -v "$(M2)":/m2 -v "$(M2_HOME)":/m2home \
	-w /ws $(MAVEN_IMAGE) mvn -B -Dmaven.repo.local=/m2

test:                         ## Run the test suite (starts real containers)
	@mkdir -p "$(M2)" "$(M2_HOME)"
	@docker pull -q openanalytics/shinyproxy-integration-test-app >/dev/null
	$(MVN_DOCKER) test

dev: build                    ## Build, then bring the dev stack up
	$(COMPOSE) up --build -d
	@echo
	@echo "  platform   http://localhost:8080   (alice/alice, bob/bob)"
	@echo "  keycloak   http://localhost:8081   (admin/admin)"
	@echo "  minio      http://localhost:9001   (skald/skaldskald)"
	@echo "  registry   http://localhost:5000"
	@echo "  postgres   localhost:55432         (skald/skald/skald)"

down:                         ## Stop the dev stack
	$(COMPOSE) down

logs:                         ## Follow platform logs
	$(COMPOSE) logs -f skald

clean:                        ## Remove build output and stack volumes
	$(COMPOSE) down -v
	rm -rf target

shell:                        ## Shell into the Maven build image
	@mkdir -p "$(M2)" "$(M2_HOME)"
	docker run --rm -it -u $(shell id -u):$(shell id -g) -e HOME=/m2home \
		-v "$(CURDIR)":/ws -v "$(M2)":/m2 -v "$(M2_HOME)":/m2home \
		-w /ws $(MAVEN_IMAGE) bash
