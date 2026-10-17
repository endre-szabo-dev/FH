#!/bin/bash
set -e

DISTRO=$1
ACTION=$2

if [ -z "$DISTRO" ] || [ -z "$ACTION" ]; then
    echo "Usage: ./build_docker.sh [alpine|debian] [build|test]"
    exit 1
fi

if [ "$ACTION" == "build" ]; then
    echo "Building fh-$DISTRO..."
    docker build -f docker/Dockerfile.$DISTRO -t fh-$DISTRO .
elif [ "$ACTION" == "test" ]; then
    echo "Testing fh-$DISTRO..."
    docker run --rm fh-$DISTRO ./run_tests_release.sh
else
    echo "Unknown action: $ACTION"
    echo "Usage: ./build_docker.sh [alpine|debian] [build|test]"
    exit 1
fi
