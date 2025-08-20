REGISTRY_NAME = kind-registry
REGISTRY_HOST = localhost
REGISTRY_PORT = 5002

IMG ?= ${REGISTRY_HOST}:${REGISTRY_PORT}/kubernetes-cedar-authorizer:latest

DOCKER ?= docker

.PHONY: registry
registry:
	if [[ "$$(${DOCKER} inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || true)" != 'true' ]]; then \
		${DOCKER} run \
			-d --restart=always -p "127.0.0.1:${REGISTRY_PORT}:5000" --pull always --network bridge --name "${REGISTRY_NAME}" \
			registry:2; \
	fi

.PHONY: image-build
image-build:
	$(DOCKER) build -t ${IMG} .
	[[ "${IMG}" == ${REGISTRY_HOST}:${REGISTRY_PORT}/* ]] && $(DOCKER) push $(IMG)

.PHONY: kind
kind: image-build registry
	@echo "Deleting previous kind cluster"
	kind delete cluster --name kubernetes-cedar-authorizer
	# TODO: Populate localdev/mount/certs with certs for the webhook
	@echo "Creating kind cluster without the Cedar authorizer during bootstrapping"
	cp localdev/apiserver-authz-config-without-webhook.yaml localdev/mount/apiserver-authz-config.yaml
	kind create cluster --config localdev/kind.yaml
	@echo "Creating kubeconfig for the authorizing webhook to communicate with the API server"
	$(DOCKER) exec -it kubernetes-cedar-authorizer-control-plane \
		/bin/sh -c '/usr/bin/kubeadm kubeconfig user \
		--org system:authorizers \
		--client-name system:authorizer:kubernetes-cedar-authorizer \
		--validity-period 744h > /kubernetes-cedar-authorizer/webhook-kubeconfig.yaml'
	kubectl apply -f localdev/webhook-rbac.yaml

	./localdev/kind-with-registry.sh
	@echo "Waiting for webhook to start up and generate certificates"
	while [[ ! -f localdev/mount/certs/server.crt ]]; do sleep 1; done
	@echo "Webhook have started, configure Kubernetes to authorize using it"
	cp localdev/apiserver-authz-config-with-webhook.yaml localdev/mount/apiserver-authz-config.yaml


.PHONY: reviewable
reviewable:
	cargo fmt
	cargo test
