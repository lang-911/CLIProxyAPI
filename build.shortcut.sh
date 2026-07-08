#!/bin/sh
set -e
set -u

CPA_VERSION=v7.2.52-1

./build.sh ${CPA_VERSION} \
 && mv cli-proxy-api_${CPA_VERSION}_darwin_amd64 ~/.cli-proxy-api/ \
 && ln -sf ~/.cli-proxy-api/cli-proxy-api_${CPA_VERSION}_darwin_amd64 ~/.cli-proxy-api/cpa \
 && launchctl kickstart -k gui/$(id -u)/com.lang-911.cpa
