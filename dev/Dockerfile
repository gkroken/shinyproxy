# Dev runtime image for the platform. Expects `make build` to have produced the jar.
FROM eclipse-temurin:21-jre

RUN groupadd -r skald && useradd -r -g skald skald
WORKDIR /opt/skald
COPY --chown=skald:skald target/*-exec.jar /opt/skald/skald.jar

# The platform talks to the Docker daemon, so it needs the socket group at runtime;
# docker-compose supplies the group. Content and build containers never get the socket.
USER skald
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/opt/skald/skald.jar"]
