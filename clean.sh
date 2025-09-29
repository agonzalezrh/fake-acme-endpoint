#!/bin/bash

# Cleanup script for Fake ACME Endpoint on OpenShift 4
# This script removes all resources created by the deployment

set -e

# Configuration
NAMESPACE="${NAMESPACE:-fake-acme}"

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

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --namespace NAME  OpenShift namespace (default: fake-acme)"
    echo "  --keep-pvc           Keep PersistentVolumeClaim (preserve data)"
    echo "  --keep-namespace     Keep namespace (only delete resources inside)"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Clean everything in fake-acme namespace"
    echo "  $0 --keep-pvc                   # Clean but preserve data"
    echo "  $0 --namespace my-namespace     # Clean specific namespace"
    echo "  $0 --keep-namespace             # Delete resources but keep namespace"
}

# Parse command line arguments
KEEP_PVC=false
KEEP_NAMESPACE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --keep-pvc)
            KEEP_PVC=true
            shift
            ;;
        --keep-namespace)
            KEEP_NAMESPACE=true
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

# Check if oc is available
if ! command -v oc &> /dev/null; then
    print_status "ERROR" "oc CLI is not installed"
    exit 1
fi

# Check if logged in to OpenShift
if ! oc whoami &> /dev/null; then
    print_status "ERROR" "Not logged in to OpenShift"
    print_status "INFO" "Please log in using: oc login <cluster-url>"
    exit 1
fi

# Check if namespace exists
if ! oc get namespace $NAMESPACE &> /dev/null; then
    print_status "WARNING" "Namespace $NAMESPACE does not exist"
    exit 0
fi

echo "Fake ACME Endpoint - Cleanup"
echo "============================"
echo "Namespace: $NAMESPACE"
echo "Keep PVC: $KEEP_PVC"
echo "Keep Namespace: $KEEP_NAMESPACE"
echo ""

# Ask for confirmation
print_status "WARNING" "This will delete resources in namespace: $NAMESPACE"
read -p "Are you sure you want to continue? (yes/no): " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    print_status "INFO" "Cleanup cancelled"
    exit 0
fi

echo ""
print_status "INFO" "Starting cleanup..."
echo ""

# Delete Route
print_status "INFO" "Deleting Route..."
if oc delete route fake-acme-route -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "Route deleted"
else
    print_status "WARNING" "Failed to delete Route"
fi

# Delete Service
print_status "INFO" "Deleting Service..."
if oc delete service fake-acme-service -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "Service deleted"
else
    print_status "WARNING" "Failed to delete Service"
fi

# Delete Deployment
print_status "INFO" "Deleting Deployment..."
if oc delete deployment fake-acme -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "Deployment deleted"
else
    print_status "WARNING" "Failed to delete Deployment"
fi

# Delete ConfigMap
print_status "INFO" "Deleting ConfigMap..."
if oc delete configmap fake-acme-config -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "ConfigMap deleted"
else
    print_status "WARNING" "Failed to delete ConfigMap"
fi

# Delete Secret
print_status "INFO" "Deleting Secret..."
if oc delete secret upstream-acme-secret -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "Secret deleted"
else
    print_status "WARNING" "Failed to delete Secret"
fi

# Delete BuildConfig
print_status "INFO" "Deleting BuildConfig..."
if oc delete buildconfig fake-acme -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "BuildConfig deleted"
else
    print_status "WARNING" "Failed to delete BuildConfig"
fi

# Delete ImageStream
print_status "INFO" "Deleting ImageStream..."
if oc delete imagestream fake-acme -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "ImageStream deleted"
else
    print_status "WARNING" "Failed to delete ImageStream"
fi

# Delete Builds
print_status "INFO" "Deleting Builds..."
if oc delete builds -l buildconfig=fake-acme -n $NAMESPACE --ignore-not-found=true; then
    print_status "SUCCESS" "Builds deleted"
else
    print_status "WARNING" "Failed to delete Builds"
fi

# Delete PVC (if not keeping)
if [ "$KEEP_PVC" = false ]; then
    print_status "INFO" "Deleting PersistentVolumeClaim..."
    if oc delete pvc fake-acme-pvc -n $NAMESPACE --ignore-not-found=true; then
        print_status "SUCCESS" "PersistentVolumeClaim deleted"
    else
        print_status "WARNING" "Failed to delete PersistentVolumeClaim"
    fi
else
    print_status "INFO" "Keeping PersistentVolumeClaim (data preserved)"
fi

# Delete Namespace (if not keeping)
if [ "$KEEP_NAMESPACE" = false ]; then
    print_status "INFO" "Deleting Namespace..."
    if oc delete namespace $NAMESPACE --ignore-not-found=true; then
        print_status "SUCCESS" "Namespace deleted"
    else
        print_status "WARNING" "Failed to delete Namespace"
    fi
else
    print_status "INFO" "Keeping Namespace"
fi

echo ""
print_status "SUCCESS" "Cleanup completed!"
echo ""

# Show remaining resources if keeping namespace
if [ "$KEEP_NAMESPACE" = true ]; then
    print_status "INFO" "Remaining resources in namespace $NAMESPACE:"
    oc get all -n $NAMESPACE 2>/dev/null || print_status "INFO" "No resources remaining"
    
    if [ "$KEEP_PVC" = true ]; then
        echo ""
        print_status "INFO" "PersistentVolumeClaim status:"
        oc get pvc -n $NAMESPACE 2>/dev/null || print_status "INFO" "No PVC found"
    fi
fi