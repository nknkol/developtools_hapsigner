#!/bin/bash
# run-build.sh — pull dockerharmony, run build inside, output binary
set -e

IMAGE="hqzing/dockerharmony:latest"
NAME="ohos-build"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ">>> Pulling ${IMAGE} ..."
docker pull ${IMAGE}

echo ">>> Starting container ..."
docker rm -f ${NAME} 2>/dev/null || true
podman run -itd --name ${NAME} --network=host ${IMAGE}

echo ">>> Copying build script into container ..."
docker cp "${SCRIPT_DIR}/build-in-dockerharmony.sh" ${NAME}:/tmp/

echo ">>> Running build ..."
docker exec -it ${NAME} sh /tmp/build-in-dockerharmony.sh

echo ">>> Copying binary out ..."
docker cp ${NAME}:/tmp/build/build/binary-sign-tool "${SCRIPT_DIR}/build/"

echo ">>> Done: $(ls -lh "${SCRIPT_DIR}/build/binary-sign-tool")"
