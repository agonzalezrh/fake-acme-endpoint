# Fake ACME Endpoint for OpenShift 4

A comprehensive fake ACME endpoint application designed for OpenShift 4 that provides certificate management with user management capabilities, upstream ACME integration, and support for both HTTP-01 and DNS-01 challenges.

## Features

- **Fake ACME Endpoint**: Implements ACME protocol endpoints for certificate management
- **User Management**: RESTful API for creating and managing temporary users
- **Upstream Integration**: Support for ZeroSSL with Let's Encrypt fallback
- **Challenge Support**: HTTP-01 and DNS-01 challenge handlers
- **Persistent Storage**: SQLite database with PVC for data persistence
- **OpenShift Ready**: Complete deployment manifests with Edge Route termination
- **Testing**: Comprehensive test scripts using certbot

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client        │    │   Fake ACME     │    │   Upstream      │
│   (certbot)     │◄──►│   Endpoint      │◄──►│   ACME          │
│                 │    │   (Flask)       │    │   (ZeroSSL/LE)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Persistent    │
                       │   Storage       │
                       │   (SQLite/PVC)  │
                       └─────────────────┘
```

## Components

### 1. Flask Application (`app.py`)
- ACME protocol implementation
- User management API
- Challenge handlers (HTTP-01, DNS-01)
- Upstream ACME integration
- Persistent data storage

### 2. OpenShift Deployment (`openshift-deployment.yaml`)
- Namespace configuration
- Secrets for upstream authentication
- ConfigMap for application settings
- PersistentVolumeClaim for data storage
- Deployment with health checks
- Service and Route with Edge termination

### 3. Testing Scripts
- `test-certbot.sh`: Basic certbot integration testing
- `test-scenarios.sh`: Comprehensive test scenarios

## Prerequisites

- OpenShift 4 cluster
- `oc` CLI tool
- certbot (for testing, optional)

## Quick Start

### 1. Deploy to OpenShift

The deployment script will build the container image on OpenShift and deploy automatically:

```bash
# Deploy using the automated script (builds on OpenShift)
./deploy.sh --host fake-acme.your-domain.com --api-key your-zerossl-key

# Or deploy using the OpenShift manifests directly
oc apply -f openshift-build.yaml
oc start-build fake-acme --follow
oc apply -f openshift-deployment.yaml
```

The application is built directly on OpenShift using BuildConfig, so you don't need Podman or Docker locally.

### 2. Configure Secrets

Update the ZeroSSL API key in the secret:

```bash
oc create secret generic upstream-acme-secret \
  --from-literal=zerossl-api-key="your-zerossl-api-key" \
  --from-literal=letsencrypt-directory="https://acme-v02.api.letsencrypt.org/directory" \
  -n fake-acme
```

### 3. Update Route Host

Update the Route hostname in `openshift-deployment.yaml`:

```yaml
spec:
  host: fake-acme.your-domain.com  # Update this
```

### 4. Deploy

```bash
oc apply -f openshift-deployment.yaml
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_PATH` | SQLite database path | `/data/fake_acme.db` |
| `ZEROSSL_API_KEY` | ZeroSSL API key | - |
| `ACME_DIRECTORY_URL` | ACME directory URL | Let's Encrypt |
| `LETSENCRYPT_FALLBACK` | Enable Let's Encrypt fallback | `true` |
| `CHALLENGE_PORT` | Challenge handler port | `8080` |
| `DNS_CHALLENGE_DOMAIN` | DNS challenge domain | `acme-challenge.example.com` |

### Upstream ACME Configuration

The application supports two upstream ACME providers:

1. **ZeroSSL** (Primary)
   - Requires API key
   - Configured via `ZEROSSL_API_KEY` environment variable

2. **Let's Encrypt** (Fallback)
   - No API key required
   - Automatically used when ZeroSSL fails

## API Endpoints

### ACME Protocol Endpoints

- `GET /acme/directory` - ACME directory
- `HEAD/GET /acme/new-nonce` - Get nonce
- `POST /acme/new-account` - Create account
- `POST /acme/new-order` - Create certificate order
- `GET /acme/order/{id}/auth/{auth_id}` - Get authorization
- `POST /acme/challenge/{order_id}/{type}` - Respond to challenge
- `GET /.well-known/acme-challenge/{token}` - HTTP-01 challenge

### User Management API

- `GET /api/users` - List users
- `POST /api/users` - Create user
- `GET /api/users/{username}` - Get user
- `DELETE /api/users/{username}` - Delete user

### Health Check

- `GET /health` - Health check endpoint

## Testing

### Basic Testing

```bash
# Test basic functionality
./test-certbot.sh

# Test comprehensive scenarios
./test-scenarios.sh
```

### Certbot Integration

```bash
# Test with certbot (HTTP-01)
certbot certonly --manual \
  --preferred-challenges http \
  --server https://fake-acme.your-domain.com/acme/directory \
  -d test.example.com \
  --email test@example.com \
  --agree-tos --no-eff-email

# Test with certbot (DNS-01)
certbot certonly --manual \
  --preferred-challenges dns \
  --server https://fake-acme.your-domain.com/acme/directory \
  -d test.example.com \
  --email test@example.com \
  --agree-tos --no-eff-email
```

## User Management

### Create User

```bash
curl -X POST https://fake-acme.your-domain.com/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com"}'
```

### List Users

```bash
curl https://fake-acme.your-domain.com/api/users
```

### Delete User

```bash
curl -X DELETE https://fake-acme.your-domain.com/api/users/testuser
```

## Challenge Types

### HTTP-01 Challenge

The application automatically handles HTTP-01 challenges by serving the required response at:

```
/.well-known/acme-challenge/{token}
```

### DNS-01 Challenge

DNS-01 challenges require manual DNS record creation. The application provides the required DNS record information through the challenge response.

## Monitoring and Logs

### View Logs

```bash
# View application logs
oc logs -f deployment/fake-acme -n fake-acme

# View specific pod logs
oc logs -f pod/fake-acme-xxxxx -n fake-acme
```

### Health Check

```bash
# Check application health
curl https://fake-acme.your-domain.com/health
```

## Troubleshooting

### Common Issues

1. **Route not accessible**
   - Check Route configuration
   - Verify DNS resolution
   - Check OpenShift ingress controller

2. **Database errors**
   - Verify PVC is mounted correctly
   - Check storage class configuration
   - Ensure sufficient storage space

3. **Upstream ACME failures**
   - Verify API keys are correct
   - Check network connectivity
   - Review upstream service status

### Debug Mode

Enable debug logging by setting environment variable:

```bash
oc set env deployment/fake-acme FLASK_ENV=development -n fake-acme
```

## Security Considerations

- API keys are stored in OpenShift secrets
- Database is stored in persistent volume
- Route uses Edge termination for HTTPS
- Input validation on all endpoints
- Rate limiting should be implemented in production

## Production Deployment

For production deployment, consider:

1. **Resource Limits**: Adjust CPU/memory limits based on load
2. **Scaling**: Configure horizontal pod autoscaling
3. **Monitoring**: Add Prometheus metrics and Grafana dashboards
4. **Backup**: Implement database backup strategy
5. **Security**: Add authentication and authorization
6. **Rate Limiting**: Implement rate limiting for API endpoints

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:

- Create an issue in the repository
- Check the troubleshooting section
- Review the OpenAPI specification in `openapi.yaml`