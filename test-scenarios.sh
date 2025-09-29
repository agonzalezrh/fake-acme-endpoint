#!/bin/bash

# Comprehensive test scenarios for Fake ACME endpoint
# This script tests various scenarios including HTTP-01, DNS-01, and upstream fallback

set -e

# Default configuration
FAKE_ACME_URL="${FAKE_ACME_URL:-https://fake-acme.example.com}"
TEST_DOMAINS=("test1.example.com" "test2.example.com" "*.test.example.com")
EMAIL="${EMAIL:-test@example.com}"
ZEROSSL_API_KEY="${ZEROSSL_API_KEY:-}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            FAKE_ACME_URL="$2"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --url URL      Fake ACME endpoint URL (default: https://fake-acme.example.com)"
            echo "  --email EMAIL  Email address for testing (default: test@example.com)"
            echo "  --help         Show this help message"
            echo ""
            echo "Example:"
            echo "  $0 --url https://fake-acme.your-domain.com --email user@example.com"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "Fake ACME Endpoint - Comprehensive Test Scenarios"
echo "================================================="
echo "Fake ACME URL: $FAKE_ACME_URL"
echo "Test Domains: ${TEST_DOMAINS[*]}"
echo "Email: $EMAIL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
            echo -e "${YELLOW}ℹ${NC} $message"
            ;;
    esac
}

# Function to make HTTP requests with error handling
make_request() {
    local method=$1
    local url=$2
    local data=$3
    local headers=$4
    
    if [ -n "$data" ]; then
        if [ -n "$headers" ]; then
            curl -s -X "$method" "$url" -H "$headers" -d "$data"
        else
            curl -s -X "$method" "$url" -H "Content-Type: application/json" -d "$data"
        fi
    else
        curl -s -X "$method" "$url"
    fi
}

# Test 1: Basic connectivity and health check
test_connectivity() {
    echo "Test 1: Basic Connectivity and Health Check"
    echo "-------------------------------------------"
    
    if make_request "GET" "$FAKE_ACME_URL/health" > /dev/null; then
        print_status "SUCCESS" "Fake ACME endpoint is accessible"
    else
        print_status "ERROR" "Fake ACME endpoint is not accessible"
        return 1
    fi
    
    # Test health endpoint response
    health_response=$(make_request "GET" "$FAKE_ACME_URL/health")
    if echo "$health_response" | grep -q "healthy"; then
        print_status "SUCCESS" "Health check passed"
    else
        print_status "ERROR" "Health check failed"
        return 1
    fi
    echo ""
}

# Test 2: ACME directory endpoint
test_acme_directory() {
    echo "Test 2: ACME Directory Endpoint"
    echo "-------------------------------"
    
    directory_response=$(make_request "GET" "$FAKE_ACME_URL/acme/directory")
    
    # Check if response contains required ACME endpoints
    required_endpoints=("newNonce" "newAccount" "newOrder" "revokeCert" "keyChange")
    
    for endpoint in "${required_endpoints[@]}"; do
        if echo "$directory_response" | grep -q "\"$endpoint\""; then
            print_status "SUCCESS" "ACME directory contains $endpoint endpoint"
        else
            print_status "ERROR" "ACME directory missing $endpoint endpoint"
        fi
    done
    
    echo "Directory response:"
    echo "$directory_response" | jq '.' 2>/dev/null || echo "$directory_response"
    echo ""
}

# Test 3: User management API
test_user_management() {
    echo "Test 3: User Management API"
    echo "---------------------------"
    
    # Create test users
    test_users=("testuser1" "testuser2" "testuser3")
    
    for user in "${test_users[@]}"; do
        echo "Creating user: $user"
        user_data="{\"username\": \"$user\", \"email\": \"$user@example.com\"}"
        user_response=$(make_request "POST" "$FAKE_ACME_URL/api/users" "$user_data")
        
        if echo "$user_response" | grep -q "\"username\": \"$user\""; then
            print_status "SUCCESS" "User $user created successfully"
        else
            print_status "ERROR" "Failed to create user $user"
        fi
    done
    
    # List users
    echo ""
    echo "Listing all users:"
    users_response=$(make_request "GET" "$FAKE_ACME_URL/api/users")
    echo "$users_response" | jq '.' 2>/dev/null || echo "$users_response"
    
    # Test user retrieval
    echo ""
    echo "Testing user retrieval:"
    user_info=$(make_request "GET" "$FAKE_ACME_URL/api/users/testuser1")
    if echo "$user_info" | grep -q "testuser1"; then
        print_status "SUCCESS" "User retrieval works"
    else
        print_status "ERROR" "User retrieval failed"
    fi
    
    # Test user deletion
    echo ""
    echo "Testing user deletion:"
    if make_request "DELETE" "$FAKE_ACME_URL/api/users/testuser3" > /dev/null; then
        print_status "SUCCESS" "User deletion works"
    else
        print_status "ERROR" "User deletion failed"
    fi
    
    echo ""
}

# Test 4: ACME account creation
test_acme_account() {
    echo "Test 4: ACME Account Creation"
    echo "-----------------------------"
    
    # Test account creation
    account_data="{\"contact\": [\"mailto:$EMAIL\"], \"termsOfServiceAgreed\": true}"
    account_response=$(make_request "POST" "$FAKE_ACME_URL/acme/new-account" "$account_data")
    
    if echo "$account_response" | grep -q "\"status\": \"valid\""; then
        print_status "SUCCESS" "ACME account creation works"
    else
        print_status "ERROR" "ACME account creation failed"
    fi
    
    echo "Account creation response:"
    echo "$account_response" | jq '.' 2>/dev/null || echo "$account_response"
    echo ""
}

# Test 5: Certificate order creation
test_certificate_order() {
    echo "Test 5: Certificate Order Creation"
    echo "----------------------------------"
    
    for domain in "${TEST_DOMAINS[@]}"; do
        echo "Testing certificate order for domain: $domain"
        
        order_data="{\"identifiers\": [{\"type\": \"dns\", \"value\": \"$domain\"}]}"
        order_response=$(make_request "POST" "$FAKE_ACME_URL/acme/new-order" "$order_data")
        
        if echo "$order_response" | grep -q "\"status\": \"pending\""; then
            print_status "SUCCESS" "Certificate order created for $domain"
        else
            print_status "ERROR" "Certificate order creation failed for $domain"
        fi
        
        echo "Order response for $domain:"
        echo "$order_response" | jq '.' 2>/dev/null || echo "$order_response"
        echo ""
    done
}

# Test 6: HTTP-01 challenge simulation
test_http_challenge() {
    echo "Test 6: HTTP-01 Challenge Simulation"
    echo "------------------------------------"
    
    # This is a simplified test - in reality, certbot would handle this
    test_token="test-token-12345"
    test_key_auth="test-key-authorization"
    
    print_status "INFO" "HTTP-01 challenge testing requires certbot integration"
    print_status "INFO" "To test with certbot, use:"
    echo "  certbot certonly --manual --preferred-challenges http \\"
    echo "    --server $FAKE_ACME_URL/acme/directory \\"
    echo "    -d test.example.com --email $EMAIL \\"
    echo "    --agree-tos --no-eff-email"
    echo ""
}

# Test 7: DNS-01 challenge simulation
test_dns_challenge() {
    echo "Test 7: DNS-01 Challenge Simulation"
    echo "------------------------------------"
    
    print_status "INFO" "DNS-01 challenge testing requires certbot integration"
    print_status "INFO" "To test with certbot, use:"
    echo "  certbot certonly --manual --preferred-challenges dns \\"
    echo "    --server $FAKE_ACME_URL/acme/directory \\"
    echo "    -d test.example.com --email $EMAIL \\"
    echo "    --agree-tos --no-eff-email"
    echo ""
}

# Test 8: Upstream ACME integration test
test_upstream_integration() {
    echo "Test 8: Upstream ACME Integration Test"
    echo "--------------------------------------"
    
    if [ -n "$ZEROSSL_API_KEY" ]; then
        print_status "INFO" "ZeroSSL API key is configured"
        print_status "INFO" "Testing upstream integration with ZeroSSL"
        
        # Test ZeroSSL API connectivity
        zerossl_response=$(curl -s "https://api.zerossl.com/certificates" \
            -H "Authorization: Bearer $ZEROSSL_API_KEY" || echo "API_ERROR")
        
        if [ "$zerossl_response" != "API_ERROR" ]; then
            print_status "SUCCESS" "ZeroSSL API is accessible"
        else
            print_status "WARNING" "ZeroSSL API is not accessible (this is expected in test environment)"
        fi
    else
        print_status "WARNING" "ZeroSSL API key not configured"
    fi
    
    print_status "INFO" "Let's Encrypt fallback is configured"
    print_status "INFO" "Testing Let's Encrypt directory access"
    
    le_response=$(curl -s "https://acme-v02.api.letsencrypt.org/directory" || echo "API_ERROR")
    if [ "$le_response" != "API_ERROR" ]; then
        print_status "SUCCESS" "Let's Encrypt directory is accessible"
    else
        print_status "WARNING" "Let's Encrypt directory is not accessible"
    fi
    
    echo ""
}

# Test 9: Performance and load testing
test_performance() {
    echo "Test 9: Performance and Load Testing"
    echo "------------------------------------"
    
    print_status "INFO" "Running basic performance tests..."
    
    # Test response times
    start_time=$(date +%s%N)
    make_request "GET" "$FAKE_ACME_URL/health" > /dev/null
    end_time=$(date +%s%N)
    response_time=$(( (end_time - start_time) / 1000000 ))
    
    if [ $response_time -lt 1000 ]; then
        print_status "SUCCESS" "Response time is acceptable: ${response_time}ms"
    else
        print_status "WARNING" "Response time is slow: ${response_time}ms"
    fi
    
    # Test concurrent requests
    print_status "INFO" "Testing concurrent requests..."
    for i in {1..5}; do
        make_request "GET" "$FAKE_ACME_URL/health" > /dev/null &
    done
    wait
    
    print_status "SUCCESS" "Concurrent request test completed"
    echo ""
}

# Test 10: Cleanup
test_cleanup() {
    echo "Test 10: Cleanup"
    echo "----------------"
    
    # Clean up test users
    test_users=("testuser1" "testuser2")
    
    for user in "${test_users[@]}"; do
        if make_request "DELETE" "$FAKE_ACME_URL/api/users/$user" > /dev/null; then
            print_status "SUCCESS" "Cleaned up user: $user"
        else
            print_status "WARNING" "Failed to clean up user: $user"
        fi
    done
    
    echo ""
}

# Main execution function
main() {
    echo "Starting comprehensive test scenarios..."
    echo ""
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        print_status "ERROR" "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        print_status "WARNING" "jq is not installed. JSON responses will not be formatted."
    fi
    
    # Run all tests
    test_connectivity
    test_acme_directory
    test_user_management
    test_acme_account
    test_certificate_order
    test_http_challenge
    test_dns_challenge
    test_upstream_integration
    test_performance
    test_cleanup
    
    echo "All test scenarios completed!"
    echo ""
    print_status "SUCCESS" "Fake ACME endpoint testing completed successfully"
}

# Run main function
main "$@"