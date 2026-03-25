FROM debian:bookworm-slim AS drogon-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG DROGON_VERSION=v1.9.11

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libc-ares-dev \
    libjsoncpp-dev \
    libsqlite3-dev \
    libssl-dev \
    ninja-build \
    pkg-config \
    uuid-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --recursive --shallow-submodules --branch ${DROGON_VERSION} https://github.com/drogonframework/drogon.git /tmp/drogon \
    && cmake -S /tmp/drogon -B /tmp/drogon/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/drogon \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_ORM=OFF \
        -DBUILD_CTL=OFF \
    && cmake --build /tmp/drogon/build \
    && cmake --install /tmp/drogon/build \
    && rm -rf /tmp/drogon

FROM debian:bookworm-slim AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    libc-ares-dev \
    libjsoncpp-dev \
    libsqlite3-dev \
    libssl-dev \
    ninja-build \
    pkg-config \
    uuid-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=drogon-builder /opt/drogon /opt/drogon

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /src/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH=/opt/drogon \
        -DBUILD_TESTING=OFF \
    && cmake --build /src/build --target roche-limit roche_limit_cli

FROM debian:bookworm-slim AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gosu \
    libc-ares2 \
    libjsoncpp25 \
    libsqlite3-0 \
    libssl3 \
    libstdc++6 \
    libuuid1 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 roche-limit \
    && useradd --system --uid 10001 --gid roche-limit --home /app roche-limit \
    && mkdir -p /app/schema /var/lib/roche-limit \
    && chown -R roche-limit:roche-limit /app /var/lib/roche-limit

COPY --from=drogon-builder /opt/drogon /opt/drogon
COPY --from=builder /src/build/server/roche-limit /app/roche-limit
COPY --from=builder /src/build/tools/roche_limit_cli/roche_limit_cli /usr/local/bin/roche_limit_cli
COPY schema/init.sql /app/schema/init.sql
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/roche_limit_cli

WORKDIR /app
ENV LD_LIBRARY_PATH=/opt/drogon/lib

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/app/roche-limit"]
