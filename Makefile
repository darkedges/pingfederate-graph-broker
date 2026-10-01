.PHONY: test build build-portal build-portal-ui run run-portal portal restart-pf-stack \
	image-broker image-portal compose-pf compose-broker compose-portal compose-down \
	demo-up demo-down helm-lint helm-template helm-upgrade
test:
	go test -race -count=1 ./...
	go vet ./...
build:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/directory-broker ./cmd/broker
build-portal:
	mkdir -p bin
	go build -buildvcs=false -trimpath -o bin/directory-portal ./cmd/portal
run:
	go run ./cmd/broker
build-portal-ui:
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web build
	pwsh -NoProfile -File scripts/build-portal-ui.ps1
run-portal: export GOCACHE := $(CURDIR)/.go-cache
run-portal:
	go run ./cmd/portal -env-file .env
portal: run-portal
image-broker:
	docker build --target broker -t pingfederate-graph-broker-broker:latest .
image-portal:
	docker build --target portal -t pingfederate-graph-broker-portal:latest .
compose-pf:
	docker compose -f compose.yaml up -d pingfederate
restart-pf-stack:
	pwsh -NoProfile -File scripts/restart-pf-stack.ps1
compose-broker:
	docker compose -f compose.yaml --profile broker up --build -d broker
compose-portal:
	docker compose -f compose.yaml --profile broker --profile portal up --build -d portal
compose-down:
	docker compose -f compose.yaml --profile broker --profile portal down
demo-up:
	docker compose -f compose.demo.yaml up --build -d
demo-down:
	docker compose -f compose.demo.yaml down
helm-lint:
	helm lint helm/broker
helm-template:
	helm template directory-broker helm/broker
helm-upgrade:
	helm upgrade --install directory-broker helm/broker --namespace directory-broker --create-namespace -f $(HELM_VALUES)
