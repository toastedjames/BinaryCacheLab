#!/bin/bash
# Runs the two outstanding qualification gates from a fresh copy of this toolkit.
set -euo pipefail
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for file in binarycachelab.jar binarycachelab.jar.sha256 bcl .dockerignore qualification/Dockerfile qualification/run-clean.sh; do
    [ -f "$SOURCE/$file" ] || { printf 'Missing current toolkit file: %s\n' "$SOURCE/$file" >&2; exit 2; }
done
[ "$(uname -s)" = Linux ] || { printf 'Run this script inside Linux/WSL.\n' >&2; exit 7; }
DEST=$(mktemp -d "$HOME/BinaryCacheLab-qualification-XXXXXXXX")
mkdir "$DEST/scripts" "$DEST/qualification"
cp "$SOURCE/binarycachelab.jar" "$SOURCE/binarycachelab.jar.sha256" "$SOURCE/bcl" "$SOURCE/.dockerignore" "$DEST/"
cp "$SOURCE/scripts/"*.py "$SOURCE/scripts/qualify-clean-linux.sh" "$DEST/scripts/"
cp "$SOURCE/qualification/Dockerfile" "$SOURCE/qualification/run-clean.sh" "$DEST/qualification/"
chmod +x "$DEST/bcl"
cd "$DEST"
exec > >(tee -a "$DEST/session.log") 2>&1
printf 'Fresh qualification installation: %s\n' "$DEST"
sha256sum -c binarycachelab.jar.sha256
packages=()
for item in 'python3:python3' 'gcc:gcc' 'clang:clang' 'nm:binutils' 'strip:binutils' 'docker:docker.io'; do
    tool=${item%%:*}; package=${item#*:}
    if ! command -v "$tool" >/dev/null 2>&1; then packages+=("$package"); fi
done
major=0
if ! command -v java >/dev/null 2>&1; then
    packages+=(openjdk-21-jdk-headless)
else
    java_version=$(java -version 2>&1 | head -n 1)
    major=$(printf '%s\n' "$java_version" | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p')
    if [ -z "$major" ] || [ "$major" -lt 17 ]; then packages+=(openjdk-21-jdk-headless); fi
fi
if [ "${#packages[@]}" -gt 0 ]; then
    command -v apt-get >/dev/null || { printf 'Missing dependencies: %s. Automatic installation requires apt-get.\n' "${packages[*]}" >&2; exit 7; }
    printf 'Installing missing qualification dependencies: %s\n' "${packages[*]}"
    sudo apt-get update
    sudo apt-get install -y "${packages[@]}"
fi
# Use the checked Linux Java executable rather than a Windows JAVA override.
JAVA=$(command -v java)
if [ -z "$major" ] || [ "$major" -lt 17 ]; then
    for candidate in /usr/lib/jvm/java-21-openjdk-*/bin/java; do
        if [ -x "$candidate" ]; then JAVA=$candidate; break; fi
    done
fi
export JAVA
export PYTHONDONTWRITEBYTECODE=1
./bcl --version
printf '\nRunning the Linux compiler/stripping matrix...\n'
native_status=0
./bcl qualify-broad --native --output "$DEST/native-evidence" || native_status=$?
printf '\nRunning the fresh OS installation gate...\n'
clean_status=0
if ! sudo docker info > "$DEST/docker-info.log" 2>&1; then
    printf 'Docker daemon is unavailable; attempting to start the installed Linux service.\n'
    sudo service docker start >> "$DEST/docker-info.log" 2>&1 || true
fi
if sudo docker info >> "$DEST/docker-info.log" 2>&1; then
    sudo bash "$DEST/scripts/qualify-clean-linux.sh" "$DEST/clean-evidence" || clean_status=$?
else
    clean_status=7
    printf 'Clean gate blocked: Docker daemon unavailable. See %s/docker-info.log\n' "$DEST"
fi
printf '\nQualification status\n====================\nNative gate exit: %s\nClean OS gate exit: %s\nEvidence directory: %s\n' "$native_status" "$clean_status" "$DEST"
if [ "$native_status" -eq 0 ] && [ "$clean_status" -eq 0 ] && [ -f "$DEST/clean-evidence/CLEAN-INSTALL-PASSED.json" ]; then
    printf 'Both remaining qualification gates passed.\n'
else
    printf 'Qualification is not complete. Retained reports identify the failed or blocked gate.\n'
    exit 7
fi
