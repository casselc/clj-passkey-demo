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

COPY src src/
COPY build.clj .
RUN clj -Srepro -Sverbose -T:build uber :uber-file target/app.jar

FROM ghcr.io/graalvm/native-image-community:21-muslib AS native-builder
RUN useradd --uid 10001 --no-create-home --home "/homeless" -c "" --shell "/sbin/nologin" app
WORKDIR /opt
COPY --from=cljs-builder /opt/dist public
COPY --from=clj-builder /opt/target/app.jar .
RUN native-image -cp public -jar app.jar -o app --no-fallback --gc=serial -R:MinHeapSize=128m -R:MaxHeapSize=768m --strict-image-heap --static --libc=musl -march=native \
    -J-Dclojure.spec.skip.macros=true -J-Dclojure.compiler.direct-linking=true -J-Dclojure.tools.logging.factory=clojure.tools.logging.impl/jul-factory \
    -H:+ReportExceptionStackTraces --report-unsupported-elements-at-runtime  --features=clj_easy.graal_build_time.InitClojureClasses --install-exit-handlers \
    --initialize-at-build-time=org.slf4j.jul.JDK14LoggerAdapter,com.yubico.webauthn.data.PublicKeyCredentialCreationOptions,org.slf4j.helpers.Reporter,org.slf4j.LoggerFactory,com.yubico.webauthn.data.ByteArray,java.sql.SQLException,org.slf4j.helpers,org.slf4j.jul.JULServiceProvider,org.slf4j.jul.JDK14LoggerFactory \
    -H:IncludeResources=".*/.*html|js|css$" --enable-http --verbose

FROM scratch AS app

EXPOSE 8090

ENV PORT=8090
ENV MALLOC_ARENA_MAX=2
ENV JDK_JAVA_OPTIONS="-XshowSettings:system -XX:+UseContainerSupport -Xmx768m -Xms128m --add-opens jdk.crypto.ec/sun.security.ec=ALL-UNNAMED --add-opens java.base/sun.security.x509=ALL-UNNAMED --add-opens java.base/sun.security.util=ALL-UNNAMED"
ENV JAVA OPTS="-Dclojure.tools.logging.factory=clojure.tools.logging.impl/log4j2-factory"

COPY --from=native-builder /opt .
COPY --from=native-builder /etc/passwd /etc/passwd
USER app

CMD ["./app", "start-server"] 