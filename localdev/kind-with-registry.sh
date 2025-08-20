#!/bin/sh
set -o errexit

# 0. Attribution: Copied from kind upstream example: https://kind.sigs.k8s.io/docs/user/local-registry/

# Steps 1 and 2 done in the Makefile

reg_name='kind-registry'
reg_port='5002'

# 3. Add the registry config to the nodes
#
# This is necessary because localhost resolves to loopback addresses that are
# network-namespace local.
# In other words: localhost in the container is not localhost on the host.
#
# We want a consistent name that works from both ends, so we tell containerd to
# alias localhost:${reg_port} to the registry container when pulling images

# TODO: Can we break the circular dependency of generating the certs before startup, instead of on startup by the Go code?

REGISTRY_DIR="/etc/containerd/certs.d/localhost:${reg_port}"
for node in $(kind get nodes -n kubernetes-cedar-authorizer); do
  docker exec "${node}" mkdir -p "${REGISTRY_DIR}"
  cat <<EOF | docker exec -i "${node}" cp /dev/stdin "${REGISTRY_DIR}/hosts.toml"
[host."http://${reg_name}:5000"]
EOF
done

# 4. Connect the registry to the cluster network if not already connected
# This allows kind to bootstrap the network but ensures they're on the same network
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  docker network connect "kind" "${reg_name}"
fi

# 5. Document the local registry
# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
#cat <<EOF | kubectl apply -f -
#apiVersion: v1
#kind: ConfigMap
#metadata:
#  name: local-registry-hosting
#  namespace: kube-public
#data:
#  localRegistryHosting.v1: |
#    host: "localhost:${reg_port}"
#    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
#EOF