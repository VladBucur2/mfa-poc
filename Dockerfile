# syntax=docker/dockerfile:1

# ---- build stage: compiles the jar and runs the unit tests (RFC test vectors) ------------
# A failing test fails the image build, so a broken TOTP implementation cannot be deployed.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B package

# ---- runtime stage: a JRE only, running as an unprivileged user --------------------------
FROM eclipse-temurin:21-jre
RUN useradd --system --create-home --uid 10001 appuser \
 && mkdir -p /app/logs \
 && chown -R appuser /app
WORKDIR /app
COPY --from=build /src/target/mfa-poc-0.1.0.jar /app/app.jar
USER appuser
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
