# Makefile for Fake ACME Endpoint

# Variables
IMAGE_NAME ?= fake-acme
IMAGE_TAG ?= latest
NAMESPACE ?= fake-acme
ROUTE_HOST ?= fake-acme.example.com
ZEROSSL_API_KEY ?= ""

# Colors
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

.PHONY: help build deploy test clean lint format

# Default target
help:
	@echo "Fake ACME Endpoint - Available Commands"
	@echo "======================================"
	@echo ""
	@echo "Development:"
	@echo "  make build          - Build container image on OpenShift"
	@echo "  make run            - Run application locally"
	@echo "  make test           - Run test scripts"
	@echo "  make lint           - Run linting checks"
	@echo "  make format         - Format code"
	@echo ""
	@echo "Deployment:"
	@echo "  make deploy         - Deploy to OpenShift"
	@echo "  make undeploy       - Remove from OpenShift"
	@echo "  make status         - Check deployment status"
	@echo ""
	@echo "Testing:"
	@echo "  make test-basic     - Run basic tests"
	@echo "  make test-full      - Run comprehensive tests"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean          - Clean up resources"
	@echo "  make logs           - View application logs"
	@echo "  make shell          - Open shell in pod"
	@echo ""
	@echo "Variables:"
	@echo "  IMAGE_NAME=$(IMAGE_NAME)"
	@echo "  IMAGE_TAG=$(IMAGE_TAG)"
	@echo "  NAMESPACE=$(NAMESPACE)"
	@echo "  ROUTE_HOST=$(ROUTE_HOST)"

# Development targets
build:
	@echo "$(GREEN)Building container image on OpenShift...$(NC)"
	oc apply -f openshift-build.yaml -n $(NAMESPACE)
	oc start-build $(IMAGE_NAME) -n $(NAMESPACE) --follow
	@echo "$(GREEN)✓ Image built on OpenShift$(NC)"

run:
	@echo "$(GREEN)Running application locally...$(NC)"
	python app.py

# Testing targets
test: test-basic

test-basic:
	@echo "$(GREEN)Running basic tests...$(NC)"
	./test-certbot.sh

test-full:
	@echo "$(GREEN)Running comprehensive tests...$(NC)"
	./test-scenarios.sh

# Code quality targets
lint:
	@echo "$(GREEN)Running linting checks...$(NC)"
	@if command -v flake8 >/dev/null 2>&1; then \
		flake8 app.py; \
	else \
		echo "$(YELLOW)flake8 not installed, skipping linting$(NC)"; \
	fi

format:
	@echo "$(GREEN)Formatting code...$(NC)"
	@if command -v black >/dev/null 2>&1; then \
		black app.py; \
	else \
		echo "$(YELLOW)black not installed, skipping formatting$(NC)"; \
	fi

# Deployment targets
deploy:
	@echo "$(GREEN)Deploying to OpenShift...$(NC)"
	./deploy.sh --namespace $(NAMESPACE) --host $(ROUTE_HOST) --api-key $(ZEROSSL_API_KEY)
	@echo "$(GREEN)✓ Deployment completed$(NC)"

undeploy:
	@echo "$(RED)Removing from OpenShift...$(NC)"
	oc delete namespace $(NAMESPACE) --ignore-not-found=true
	@echo "$(GREEN)✓ Resources removed$(NC)"

status:
	@echo "$(GREEN)Checking deployment status...$(NC)"
	@echo "Namespace: $(NAMESPACE)"
	@oc get all -n $(NAMESPACE) 2>/dev/null || echo "$(YELLOW)Namespace not found$(NC)"
	@echo ""
	@echo "Route:"
	@oc get route -n $(NAMESPACE) 2>/dev/null || echo "$(YELLOW)Route not found$(NC)"

# Utility targets
clean:
	@echo "$(GREEN)Cleaning up...$(NC)"
	oc delete buildconfig $(IMAGE_NAME) -n $(NAMESPACE) 2>/dev/null || true
	oc delete imagestream $(IMAGE_NAME) -n $(NAMESPACE) 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup completed$(NC)"

logs:
	@echo "$(GREEN)Viewing application logs...$(NC)"
	oc logs -f deployment/$(IMAGE_NAME) -n $(NAMESPACE)

shell:
	@echo "$(GREEN)Opening shell in pod...$(NC)"
	oc exec -it deployment/$(IMAGE_NAME) -n $(NAMESPACE) -- /bin/bash

# Health check
health:
	@echo "$(GREEN)Checking application health...$(NC)"
	@ROUTE_URL=$$(oc get route $(IMAGE_NAME)-route -n $(NAMESPACE) -o jsonpath='{.spec.host}' 2>/dev/null); \
	if [ -n "$$ROUTE_URL" ]; then \
		echo "Testing: https://$$ROUTE_URL/health"; \
		curl -s -f "https://$$ROUTE_URL/health" | jq . 2>/dev/null || curl -s "https://$$ROUTE_URL/health"; \
	else \
		echo "$(YELLOW)Route not found$(NC)"; \
	fi

# Install dependencies
install-deps:
	@echo "$(GREEN)Installing development dependencies...$(NC)"
	pip install -r requirements.txt
	@if command -v flake8 >/dev/null 2>&1; then \
		echo "$(GREEN)✓ flake8 already installed$(NC)"; \
	else \
		pip install flake8; \
	fi
	@if command -v black >/dev/null 2>&1; then \
		echo "$(GREEN)✓ black already installed$(NC)"; \
	else \
		pip install black; \
	fi

# Development setup
dev-setup: install-deps
	@echo "$(GREEN)Setting up development environment...$(NC)"
	@echo "Creating data directory..."
	mkdir -p data
	@echo "Setting environment variables..."
	@echo "export DATABASE_PATH=./data/fake_acme.db" > .env
	@echo "export FLASK_ENV=development" >> .env
	@echo "$(GREEN)✓ Development environment ready$(NC)"
	@echo "$(YELLOW)Run 'source .env' to activate environment$(NC)"

# Quick start
quick-start: build deploy
	@echo "$(GREEN)Quick start completed!$(NC)"
	@echo "$(YELLOW)Run 'make status' to check deployment$(NC)"
	@echo "$(YELLOW)Run 'make test' to run tests$(NC)"

# Production deployment
prod-deploy: build
	@echo "$(GREEN)Deploying to production...$(NC)"
	@echo "$(YELLOW)Please ensure you have set the following variables:$(NC)"
	@echo "  ROUTE_HOST=your-production-domain.com"
	@echo "  ZEROSSL_API_KEY=your-zerossl-api-key"
	@echo ""
	@read -p "Continue with production deployment? (y/N): " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		./deploy.sh --namespace $(NAMESPACE) --host $(ROUTE_HOST) --api-key $(ZEROSSL_API_KEY); \
	else \
		echo "$(YELLOW)Production deployment cancelled$(NC)"; \
	fi