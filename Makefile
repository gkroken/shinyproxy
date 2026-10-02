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

.PHONY: build test fuzz dev down logs clean shell

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
	@# The build-worker launcher's integration test (DockerWorkerLauncherTest) launches the
	@# real worker and gateway from the images/ Dockerfiles, with the pinned helper images.
	@docker build -q -t skald-buildkit-worker:test images/buildkit-worker >/dev/null
	@docker build -q -t skald-egress-gateway:test images/egress-gateway >/dev/null
	@docker pull -q busybox@sha256:ea2b9914a16a4ac1981994af97b318f7c7d4db76b580c56177f08bf76f4a0be8 >/dev/null
	@docker pull -q debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 >/dev/null
	$(MVN_DOCKER) test

# Coverage-guided fuzzing of the bundle parser (BundleFuzzTest). `make test` already runs
# every target once per seed as a regression; this runs each under libFuzzer for
# FUZZ_SECONDS. Jazzer fuzzes one target per JVM, so they run one after another, and the
# run stops at the first target that finds something. A finding is saved as a reproducer
# under src/test/resources/.../BundleFuzzTestInputs/<target>/, where `make test` replays it
# from then on. The growing working corpus is kept in .cifuzz-corpus/ (git-ignored), so
# repeated runs build on each other. No Docker access: the targets touch only temp files.
FUZZ_SECONDS ?= 60
FUZZ_TARGETS := gzipMember tarHeader paxRecords memberPath tarStream manifest extractor
fuzz:                         ## Fuzz the bundle parser, FUZZ_SECONDS per target (default 60)
	@mkdir -p "$(M2)" "$(M2_HOME)"
	@set -e; for target in $(FUZZ_TARGETS); do \
		echo "== fuzzing $$target for $(FUZZ_SECONDS)s"; \
		docker run --rm -u $(shell id -u):$(shell id -g) -e HOME=/m2home -e JAZZER_FUZZ=1 \
			-v "$(CURDIR)":/ws -v "$(M2)":/m2 -v "$(M2_HOME)":/m2home -w /ws $(MAVEN_IMAGE) \
			mvn -B -q -Dmaven.repo.local=/m2 -Dlicense.skip=true test \
			-Dtest="BundleFuzzTest#$$target" -Djazzer.max_duration=$(FUZZ_SECONDS)s \
			-Dsurefire.failIfNoSpecifiedTests=false; \
	done

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
