#!/bin/bash

# Test script for Fake ACME endpoint using certbot
# This script demonstrates how to use certbot with the fake ACME endpoint

set -e

# Configuration
FAKE_ACME_URL="${FAKE_ACME_URL:-https://fake-acme.example.com}"
TEST_DOMAIN="${TEST_DOMAIN:-test.example.com}"
EMAIL="${EMAIL:-test@example.com}"

echo "Testing Fake ACME endpoint with certbot"
echo "======================================"
echo "Fake ACME URL: $FAKE_ACME_URL"
echo "Test Domain: $TEST_DOMAIN"
echo "Email: $EMAIL"
echo ""

# Function to check if the fake ACME endpoint is running
check_endpoint() {
    echo "Checking if fake ACME endpoint is running..."
    if curl -s -f "$FAKE_ACME_URL/health" > /dev/null; then
        echo "✓ Fake ACME endpoint is running"
    else
        echo "✗ Fake ACME endpoint is not accessible"
        echo "Please ensure the endpoint is running and accessible at $FAKE_ACME_URL"
        exit 1
    fi
}

# Function to test ACME directory
test_directory() {
    echo ""
    echo "Testing ACME directory endpoint..."
    response=$(curl -s "$FAKE_ACME_URL/acme/directory")
    echo "Directory response:"
    echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

# Function to test user management API
test_user_management() {
    echo ""
    echo "Testing user management API..."
    
    # Create a test user
    echo "Creating test user..."
    user_response=$(curl -s -X POST "$FAKE_ACME_URL/api/users" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"testuser\", \"email\": \"$EMAIL\"}")
    echo "User creation response:"
    echo "$user_response" | jq '.' 2>/dev/null || echo "$user_response"
    
    # List users
    echo ""
    echo "Listing users..."
    users_response=$(curl -s "$FAKE_ACME_URL/api/users")
    echo "Users list:"
    echo "$users_response" | jq '.' 2>/dev/null || echo "$users_response"
}

# Function to test HTTP-01 challenge
test_http_challenge() {
    echo ""
    echo "Testing HTTP-01 challenge..."
    
    # This would typically be done by certbot, but we can simulate it
    echo "Note: HTTP-01 challenge testing requires certbot to be configured"
    echo "To test with certbot, run:"
    echo "certbot certonly --manual --preferred-challenges http --server $FAKE_ACME_URL/acme/directory -d $TEST_DOMAIN --email $EMAIL --agree-tos --no-eff-email"
}

# Function to test DNS-01 challenge
test_dns_challenge() {
    echo ""
    echo "Testing DNS-01 challenge..."
    
    echo "Note: DNS-01 challenge testing requires certbot to be configured"
    echo "To test with certbot, run:"
    echo "certbot certonly --manual --preferred-challenges dns --server $FAKE_ACME_URL/acme/directory -d $TEST_DOMAIN --email $EMAIL --agree-tos --no-eff-email"
}

# Function to run actual certbot test
run_certbot_test() {
    echo ""
    echo "Running certbot test..."
    echo "This will attempt to get a certificate using the fake ACME endpoint"
    echo ""
    
    # Check if certbot is installed
    if ! command -v certbot &> /dev/null; then
        echo "✗ certbot is not installed"
        echo "Please install certbot first:"
        echo "  Ubuntu/Debian: sudo apt-get install certbot"
        echo "  CentOS/RHEL: sudo yum install certbot"
        echo "  macOS: brew install certbot"
        return 1
    fi
    
    echo "✓ certbot is installed"
    
    # Run certbot in dry-run mode first
    echo "Running certbot in dry-run mode..."
    if certbot certonly \
        --manual \
        --preferred-challenges http \
        --server "$FAKE_ACME_URL/acme/directory" \
        -d "$TEST_DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --dry-run; then
        echo "✓ Dry run successful"
    else
        echo "✗ Dry run failed"
        return 1
    fi
}

# Function to clean up test user
cleanup() {
    echo ""
    echo "Cleaning up test user..."
    if curl -s -X DELETE "$FAKE_ACME_URL/api/users/testuser" > /dev/null; then
        echo "✓ Test user deleted"
    else
        echo "✗ Failed to delete test user"
    fi
}

# Main execution
main() {
    echo "Starting Fake ACME endpoint tests..."
    echo ""
    
    # Check if jq is available for JSON formatting
    if ! command -v jq &> /dev/null; then
        echo "Warning: jq is not installed. JSON responses will not be formatted."
        echo "Install jq for better output formatting:"
        echo "  Ubuntu/Debian: sudo apt-get install jq"
        echo "  CentOS/RHEL: sudo yum install jq"
        echo "  macOS: brew install jq"
        echo ""
    fi
    
    # Run tests
    check_endpoint
    test_directory
    test_user_management
    
    # Ask user if they want to run certbot tests
    echo ""
    read -p "Do you want to run certbot tests? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        run_certbot_test
    else
        test_http_challenge
        test_dns_challenge
    fi
    
    # Cleanup
    cleanup
    
    echo ""
    echo "Test completed!"
}

# Run main function
main "$@"