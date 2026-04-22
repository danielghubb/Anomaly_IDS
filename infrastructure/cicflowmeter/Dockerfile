# ======================
# Build Stage
# ======================
FROM maven:3.9.6-eclipse-temurin-11 AS build
WORKDIR /src

# CICFlowMeter Quellcode aus Projektstruktur kopieren
# (Build-Kontext = Projekt-Root)
COPY cicflowmeter/vendor/CICFlowMeter/ /src/

# jnetpcap ist NICHT in Maven Central -> lokal installieren
RUN mvn -q install:install-file \
    -Dfile=/src/jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
    -DgroupId=org.jnetpcap \
    -DartifactId=jnetpcap \
    -Dversion=1.4.1 \
    -Dpackaging=jar

# CICFlowMeter bauen (erzeugt JARs in /src/target)
RUN mvn -q -DskipTests clean package


# ======================
# Runtime Stage
# ======================
FROM eclipse-temurin:11-jre
WORKDIR /opt/cicflowmeter

# Alle erzeugten JARs übernehmen (Classpath-Start, KEIN java -jar)
RUN mkdir -p /opt/cicflowmeter/lib
COPY --from=build /src/target/*.jar /opt/cicflowmeter/lib/

# Native jnetpcap Libraries
COPY --from=build /src/jnetpcap/linux/jnetpcap-1.4.r1425/ /opt/cicflowmeter/jnetpcap/

# Benötigte Runtime-Tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      tcpdump iproute2 coreutils findutils \
      libpcap0.8t64 \
      libstdc++6 libgcc-s1 \
      zlib1g libc6 \
    && rm -rf /var/lib/apt/lists/* \
    && (ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so 2>/dev/null || true) \
    && (ln -sf /usr/lib/aarch64-linux-gnu/libpcap.so.0.8 /usr/lib/aarch64-linux-gnu/libpcap.so 2>/dev/null || true)
    # && ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so

# Startskript
COPY cicflowmeter/run.sh /opt/cicflowmeter/run.sh
RUN chmod +x /opt/cicflowmeter/run.sh

# jnetpcap native libs sichtbar machen
ENV LD_LIBRARY_PATH=/opt/cicflowmeter/jnetpcap

ENTRYPOINT ["/opt/cicflowmeter/run.sh"]

