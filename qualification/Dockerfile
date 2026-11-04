FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openjdk-21-jdk-headless python3 gcc clang binutils ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/BinaryCacheLab
COPY binarycachelab.jar bcl ./
COPY scripts/ ./scripts/
COPY qualification/run-clean.sh ./run-clean.sh
RUN chmod +x bcl run-clean.sh
ENV HOME=/tmp/bcl-fresh-home PYTHONDONTWRITEBYTECODE=1 JAVA=java
CMD ["sh", "./run-clean.sh"]
