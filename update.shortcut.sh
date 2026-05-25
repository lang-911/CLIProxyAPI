#!/bin/sh
set -e
set -u

CPA_VERSION=v7.1.19-1

 cp /Volumes/L/WebDAV/cpa/cli-proxy-api_${CPA_VERSION}_darwin_amd64 ~/.cli-proxy-api/ \
 && xattr -d com.apple.quarantine ~/.cli-proxy-api/cli-proxy-api_${CPA_VERSION}_darwin_amd64 \
 && chmod +x ~/.cli-proxy-api/cli-proxy-api_${CPA_VERSION}_darwin_amd64 \
 && ln -sf ~/.cli-proxy-api/cli-proxy-api_${CPA_VERSION}_darwin_amd64 ~/.cli-proxy-api/cpa \
 && launchctl kickstart -k gui/$(id -u)/com.lang-911.cpa
