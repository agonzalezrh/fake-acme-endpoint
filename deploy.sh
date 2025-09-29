#!/bin/bash

# Deployment script for Fake ACME Endpoint on OpenShift 4
# This script automates the deployment process

set -e

# Configuration
NAMESPACE="fake-acme"
APP_NAME="fake-acme"
IMAGE_NAME="fake-acme"
IMAGE_TAG="latest"
ROUTE_HOST="fake-acme.example.com"
ZEROSSL_API_KEY=""
LETSENCRYPT_FALLBACK="true"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✓${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}✗${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
    esac
}

# Function to check prerequisites
check_prerequisites() {
    print_status "INFO" "Checking prerequisites..."
    
    # Check if oc is installed
    if ! command -v oc &> /dev/null; then
        print_status "ERROR" "oc CLI is not installed"
        print_status "INFO" "Please install the OpenShift CLI: https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html"
        exit 1
    fi
    
    # Check if oc is logged in
    if ! oc whoami &> /dev/null; then
        print_status "ERROR" "Not logged in to OpenShift"
        print_status "INFO" "Please log in using: oc login <cluster-url>"
        exit 1
    fi
    
    # Check if Podman is available
    if ! command -v podman &> /dev/null; then
        print_status "WARNING" "Podman is not installed. You'll need to build the image manually."
    fi
    
    print_status "SUCCESS" "Prerequisites check completed"
}

# Function to build container image
build_image() {
    print_status "INFO" "Building container image..."
    
    if command -v podman &> /dev/null; then
        podman build -t $IMAGE_NAME:$IMAGE_TAG .
        print_status "SUCCESS" "Container image built successfully"
    else
        print_status "WARNING" "Podman not available. Please build the image manually:"
        print_status "INFO" "podman build -t $IMAGE_NAME:$IMAGE_TAG ."
    fi
}

# Function to create namespace
create_namespace() {
    print_status "INFO" "Creating namespace: $NAMESPACE"
    
    if oc get namespace $NAMESPACE &> /dev/null; then
        print_status "WARNING" "Namespace $NAMESPACE already exists"
    else
        oc create namespace $NAMESPACE
        print_status "SUCCESS" "Namespace $NAMESPACE created"
    fi
}

# Function to create secrets
create_secrets() {
    print_status "INFO" "Creating secrets..."
    
    # Create upstream ACME secret
    if [ -n "$ZEROSSL_API_KEY" ]; then
        oc create secret generic upstream-acme-secret \
            --from-literal=zerossl-api-key="$ZEROSSL_API_KEY" \
            --from-literal=letsencrypt-directory="https://acme-v02.api.letsencrypt.org/directory" \
            -n $NAMESPACE \
            --dry-run=client -o yaml | oc apply -f -
        print_status "SUCCESS" "Upstream ACME secret created"
    else
        print_status "WARNING" "ZeroSSL API key not provided. Creating secret without API key."
        oc create secret generic upstream-acme-secret \
            --from-literal=zerossl-api-key="" \
            --from-literal=letsencrypt-directory="https://acme-v02.api.letsencrypt.org/directory" \
            -n $NAMESPACE \
            --dry-run=client -o yaml | oc apply -f -
    fi
}

# Function to create configmap
create_configmap() {
    print_status "INFO" "Creating configmap..."
    
    oc create configmap fake-acme-config \
        --from-literal=ACME_DIRECTORY_URL="https://acme-v02.api.letsencrypt.org/directory" \
        --from-literal=LETSENCRYPT_FALLBACK="$LETSENCRYPT_FALLBACK" \
        --from-literal=CHALLENGE_PORT="8080" \
        --from-literal=DNS_CHALLENGE_DOMAIN="acme-challenge.example.com" \
        -n $NAMESPACE \
        --dry-run=client -o yaml | oc apply -f -
    
    print_status "SUCCESS" "ConfigMap created"
}

# Function to create PVC
create_pvc() {
    print_status "INFO" "Creating PersistentVolumeClaim..."
    
        cat <<EOF | oc apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fake-acme-pvc
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  volumeMode: Block
  # storageClassName: # Let OpenShift choose the default storage class
EOF
    
    print_status "SUCCESS" "PersistentVolumeClaim created"
}

# Function to create deployment
create_deployment() {
    print_status "INFO" "Creating deployment..."
    
    cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $APP_NAME
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
spec:
  replicas: 2
  selector:
    matchLabels:
      app: $APP_NAME
  template:
    metadata:
      labels:
        app: $APP_NAME
    spec:
      containers:
      - name: $APP_NAME
        image: $IMAGE_NAME:$IMAGE_TAG
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: DATABASE_PATH
          value: "/data/fake_acme.db"
        - name: ZEROSSL_API_KEY
          valueFrom:
            secretKeyRef:
              name: upstream-acme-secret
              key: zerossl-api-key
        - name: ACME_DIRECTORY_URL
          valueFrom:
            configMapKeyRef:
              name: fake-acme-config
              key: ACME_DIRECTORY_URL
        - name: LETSENCRYPT_FALLBACK
          valueFrom:
            configMapKeyRef:
              name: fake-acme-config
              key: LETSENCRYPT_FALLBACK
        - name: CHALLENGE_PORT
          valueFrom:
            configMapKeyRef:
              name: fake-acme-config
              key: CHALLENGE_PORT
        - name: DNS_CHALLENGE_DOMAIN
          valueFrom:
            configMapKeyRef:
              name: fake-acme-config
              key: DNS_CHALLENGE_DOMAIN
        volumeDevices:
        - name: data-storage
          devicePath: /dev/xvda
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: data-storage
        persistentVolumeClaim:
          claimName: fake-acme-pvc
EOF
    
    print_status "SUCCESS" "Deployment created"
}

# Function to create service
create_service() {
    print_status "INFO" "Creating service..."
    
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: Service
metadata:
  name: $APP_NAME-service
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
spec:
  selector:
    app: $APP_NAME
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
EOF
    
    print_status "SUCCESS" "Service created"
}

# Function to create route
create_route() {
    print_status "INFO" "Creating route..."
    
    cat <<EOF | oc apply -f -
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: $APP_NAME-route
  namespace: $NAMESPACE
  labels:
    app: $APP_NAME
spec:
  host: $ROUTE_HOST
  to:
    kind: Service
    name: $APP_NAME-service
    weight: 100
  port:
    targetPort: http
  tls:
    termination: Edge
    insecureEdgeTerminationPolicy: Redirect
  wildcardPolicy: None
EOF
    
    print_status "SUCCESS" "Route created with host: $ROUTE_HOST"
}

# Function to wait for deployment
wait_for_deployment() {
    print_status "INFO" "Waiting for deployment to be ready..."
    
    oc rollout status deployment/$APP_NAME -n $NAMESPACE --timeout=300s
    
    if [ $? -eq 0 ]; then
        print_status "SUCCESS" "Deployment is ready"
    else
        print_status "ERROR" "Deployment failed to become ready"
        exit 1
    fi
}

# Function to test deployment
test_deployment() {
    print_status "INFO" "Testing deployment..."
    
    # Get route URL
    ROUTE_URL=$(oc get route $APP_NAME-route -n $NAMESPACE -o jsonpath='{.spec.host}')
    
    if [ -n "$ROUTE_URL" ]; then
        print_status "INFO" "Testing health endpoint: https://$ROUTE_URL/health"
        
        # Test health endpoint
        if curl -s -f "https://$ROUTE_URL/health" > /dev/null; then
            print_status "SUCCESS" "Health check passed"
        else
            print_status "WARNING" "Health check failed (this might be expected if TLS is not configured)"
        fi
        
        # Test ACME directory
        print_status "INFO" "Testing ACME directory: https://$ROUTE_URL/acme/directory"
        if curl -s -f "https://$ROUTE_URL/acme/directory" > /dev/null; then
            print_status "SUCCESS" "ACME directory is accessible"
        else
            print_status "WARNING" "ACME directory test failed"
        fi
        
        print_status "INFO" "Application is available at: https://$ROUTE_URL"
    else
        print_status "ERROR" "Could not get route URL"
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --namespace NAME     OpenShift namespace (default: fake-acme)"
    echo "  -h, --host HOST          Route hostname (default: fake-acme.example.com)"
    echo "  -k, --api-key KEY        ZeroSSL API key"
    echo "  -i, --image IMAGE        Docker image name (default: fake-acme)"
    echo "  -t, --tag TAG           Docker image tag (default: latest)"
    echo "  --no-fallback           Disable Let's Encrypt fallback"
    echo "  --help                   Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --host fake-acme.mycompany.com --api-key your-zerossl-key"
    echo "  $0 --namespace my-namespace --host my-fake-acme.com"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        -h|--host)
            ROUTE_HOST="$2"
            shift 2
            ;;
        -k|--api-key)
            ZEROSSL_API_KEY="$2"
            shift 2
            ;;
        -i|--image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --no-fallback)
            LETSENCRYPT_FALLBACK="false"
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            print_status "ERROR" "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main deployment function
main() {
    print_status "INFO" "Starting Fake ACME Endpoint deployment"
    print_status "INFO" "Namespace: $NAMESPACE"
    print_status "INFO" "Route Host: $ROUTE_HOST"
    print_status "INFO" "Image: $IMAGE_NAME:$IMAGE_TAG"
    print_status "INFO" "ZeroSSL API Key: ${ZEROSSL_API_KEY:+[SET]}${ZEROSSL_API_KEY:-[NOT SET]}"
    print_status "INFO" "Let's Encrypt Fallback: $LETSENCRYPT_FALLBACK"
    echo ""
    
    check_prerequisites
    build_image
    create_namespace
    create_secrets
    create_configmap
    create_pvc
    create_deployment
    create_service
    create_route
    wait_for_deployment
    test_deployment
    
    echo ""
    print_status "SUCCESS" "Fake ACME Endpoint deployed successfully!"
    print_status "INFO" "Route URL: https://$ROUTE_HOST"
    print_status "INFO" "Health Check: https://$ROUTE_HOST/health"
    print_status "INFO" "ACME Directory: https://$ROUTE_HOST/acme/directory"
    print_status "INFO" "API Documentation: https://$ROUTE_HOST/api/docs"
    echo ""
    print_status "INFO" "To test the deployment, run:"
    print_status "INFO" "  ./test-certbot.sh --url https://$ROUTE_HOST"
    print_status "INFO" "  ./test-scenarios.sh --url https://$ROUTE_HOST"
}

# Run main function
main "$@"