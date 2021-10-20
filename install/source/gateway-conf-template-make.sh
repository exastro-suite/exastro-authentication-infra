#!/bin/bash

BASEDIR=$(dirname $0)

kubectl create cm gateway-conf-template -n exastro-gateway --dry-run=client -o yaml \
    --from-file=${BASEDIR}/epoch-system-template.conf       \
    --from-file=${BASEDIR}/epoch-ws-argocd-template.conf    \
    --from-file=${BASEDIR}/epoch-ws-ita-template.conf       \
    --from-file=${BASEDIR}/epoch-ws-sonarqube-template.conf \
    >   ${BASEDIR}/gateway-conf-template.yaml


