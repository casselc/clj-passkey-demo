FROM oven/bun:1-slim AS cljs-builder
WORKDIR /opt

COPY package.json bun.lockb ./
RUN echo Downloading CLJS deps && bun install --production

COPY cljs-build cljs-build/
COPY public public/
RUN echo Building and bundling front end && bun cljs-build/build.js

FROM clojure:temurin-21-tools-deps-1.11.1.1429-bookworm-slim AS clj-builder
WORKDIR /opt

ADD deps.edn deps.edn
RUN echo Downloading Clojure build deps && clj -Srepro -Stree -T:build
RUN echo Downloading Clojure app deps && clj -Srepro -Stree 

COPY resources resources/
COPY src src/
COPY --from=cljs-builder /opt/dist resources
COPY build.clj .
RUN clj -Srepro -Sverbose -T:build uber :uber-file target/app.jar

FROM gcr.io/distroless/java21-debian12:nonroot AS app

EXPOSE 8090

ENV PORT=8090
ENV MALLOC_ARENA_MAX=2
ENV JDK_JAVA_OPTIONS="-XshowSettings:system -XX:+UseContainerSupport -XX:MaxRAMPercentage=85 --add-opens jdk.crypto.ec/sun.security.ec=ALL-UNNAMED --add-opens java.base/sun.security.x509=ALL-UNNAMED --add-opens java.base/sun.security.util=ALL-UNNAMED"
ENV JAVA OPTS="-Dclojure.tools.logging.factory=clojure.tools.logging.impl/log4j2-factory"

WORKDIR /opt
COPY --from=clj-builder /opt/target/app.jar app.jar
COPY --from=cljs-builder /opt/dist public

CMD ["app.jar"] 