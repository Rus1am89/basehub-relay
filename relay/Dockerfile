# Ретранслятор Basehub Remote. Сборка из корня репозитория:
#   docker build -f relay/Dockerfile -t basehub-relay .
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY remote-proto remote-proto
COPY relay relay
RUN cd relay && cargo build --release --locked

FROM scratch
COPY --from=build /src/relay/target/release/basehub-relay /basehub-relay
ENV RELAY_LISTEN=0.0.0.0:8790
EXPOSE 8790
USER 65534:65534
ENTRYPOINT ["/basehub-relay"]
