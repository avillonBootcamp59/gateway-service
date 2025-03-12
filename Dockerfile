# Dockerfile para api-gateway
FROM openjdk:17-jdk-slim
VOLUME /tmp
COPY target/gateway-service-1.0.0-SNAPSHOT.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
