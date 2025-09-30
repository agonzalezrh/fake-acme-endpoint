#!/usr/bin/env python3
"""
ACME Gateway - Acts as ACME server to clients and ACME client to upstream
Returns real certificates from ZeroSSL/Let's Encrypt
"""

import os
import json
import sqlite3
import logging
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple

from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError

# ACME client libraries
import josepy as jose
from acme import client as acme_client
from acme import messages
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
ZEROSSL_EAB_KID = os.getenv('ZEROSSL_EAB_KID')
ZEROSSL_EAB_HMAC_KEY = os.getenv('ZEROSSL_EAB_HMAC_KEY')
LETSENCRYPT_FALLBACK = os.getenv('LETSENCRYPT_FALLBACK', 'true').lower() == 'true'
DATABASE_PATH = os.getenv('DATABASE_PATH', '/data/fake_acme.db')

# Upstream ACME directory URLs
ZEROSSL_DIRECTORY_URL = 'https://acme.zerossl.com/v2/DV90/directory'
LETSENCRYPT_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'

# Global upstream client
upstream_acme_client = None
upstream_provider_name = None

def init_database():
    """Initialize SQLite database"""
    try:
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    except:
        pass
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Client accounts (local)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS client_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id TEXT UNIQUE NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Orders - maps client orders to upstream orders
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_order_id INTEGER,
            upstream_order_url TEXT,
            domains TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Challenge mappings
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            domain TEXT,
            challenge_type TEXT,
            token TEXT,
            upstream_challenge_url TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (order_id) REFERENCES orders (id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_database()

def get_upstream_acme_client():
    """Get or create upstream ACME client"""
    global upstream_acme_client, upstream_provider_name
    
    if upstream_acme_client is not None:
        return upstream_acme_client, upstream_provider_name
    
    # Generate account key for upstream
    account_key = jose.JWKRSA(
        key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    )
    
    # Try ZeroSSL first
    if ZEROSSL_EAB_KID and ZEROSSL_EAB_HMAC_KEY:
        try:
            logger.info("Connecting to ZeroSSL...")
            net = acme_client.ClientNetwork(account_key, user_agent='acme-gateway/1.0')
            directory = messages.Directory.from_json(net.get(ZEROSSL_DIRECTORY_URL).json())
            acme_cl = acme_client.ClientV2(directory, net=net)
            
            # Register with EAB
            eab = messages.ExternalAccountBinding.from_data(
                account_public_key=account_key.public_key(),
                kid=ZEROSSL_EAB_KID,
                hmac_key=ZEROSSL_EAB_HMAC_KEY,
                directory=directory
            )
            
            regr = messages.NewRegistration.from_data(
                email='gateway@fake-acme.local',
                external_account_binding=eab
            )
            
            try:
                account = acme_cl.new_account(regr)
                logger.info("✓ Registered with ZeroSSL")
            except Exception as e:
                logger.info(f"ZeroSSL account exists or registration failed: {e}")
            
            upstream_acme_client = acme_cl
            upstream_provider_name = 'ZeroSSL'
            logger.info("✓ Using ZeroSSL")
            return upstream_acme_client, upstream_provider_name
            
        except Exception as e:
            logger.error(f"ZeroSSL setup failed: {e}")
    
    # Fallback to Let's Encrypt
    if LETSENCRYPT_FALLBACK:
        try:
            logger.info("Connecting to Let's Encrypt...")
            net = acme_client.ClientNetwork(account_key, user_agent='acme-gateway/1.0')
            directory = messages.Directory.from_json(net.get(LETSENCRYPT_DIRECTORY_URL).json())
            acme_cl = acme_client.ClientV2(directory, net=net)
            
            # Register without EAB
            regr = messages.NewRegistration.from_data(
                email='gateway@fake-acme.local',
                terms_of_service_agreed=True
            )
            
            try:
                account = acme_cl.new_account(regr)
                logger.info("✓ Registered with Let's Encrypt")
            except Exception as e:
                logger.info(f"Let's Encrypt account exists: {e}")
            
            upstream_acme_client = acme_cl
            upstream_provider_name = "Let's Encrypt"
            logger.info("✓ Using Let's Encrypt")
            return upstream_acme_client, upstream_provider_name
            
        except Exception as e:
            logger.error(f"Let's Encrypt setup failed: {e}")
            raise InternalServerError("Failed to connect to any upstream ACME provider")
    
    raise InternalServerError("No upstream ACME provider configured")

def add_nonce_header(response):
    """Add Replay-Nonce header to response"""
    nonce = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
    response.headers['Replay-Nonce'] = nonce
    response.headers['Cache-Control'] = 'no-store'
    return response

def parse_jws_payload():
    """Parse JWS-signed ACME request payload"""
    try:
        data = request.get_data(as_text=True)
        if not data:
            return None
        
        # Parse JWS envelope
        jws_data = json.loads(data)
        
        # Check if this is a JWS request
        if 'payload' not in jws_data:
            return jws_data
        
        # Decode payload (base64url encoded)
        payload_b64 = jws_data['payload']
        if not payload_b64:  # Empty payload for POST-as-GET
            return {}
        
        # Add padding if needed
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += '=' * padding
        
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        return payload
        
    except Exception as e:
        logger.error(f"Error parsing JWS payload: {e}")
        return None

# ACME Protocol Endpoints

@app.route('/acme/directory', methods=['GET'])
def acme_directory():
    """ACME directory endpoint"""
    base_url = request.url_root.rstrip('/')
    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')
    
    return jsonify({
        'newNonce': f'{base_url}/acme/new-nonce',
        'newAccount': f'{base_url}/acme/new-account',
        'newOrder': f'{base_url}/acme/new-order',
        'revokeCert': f'{base_url}/acme/revoke-cert',
        'keyChange': f'{base_url}/acme/key-change',
        'meta': {
            'termsOfService': f'{base_url}/terms',
            'website': f'{base_url}',
            'caaIdentities': ['acme-gateway.example.com'],
            'externalAccountRequired': False
        }
    })

@app.route('/acme/new-nonce', methods=['HEAD', 'GET'])
def new_nonce():
    """Generate new nonce"""
    response = Response('', status=200 if request.method == 'GET' else 204)
    return add_nonce_header(response)

@app.route('/acme/new-account', methods=['GET', 'POST', 'HEAD'])
def new_account():
    """Create or lookup ACME account"""
    try:
        if request.method in ['GET', 'HEAD']:
            response = Response('', status=200)
            return add_nonce_header(response)
        
        payload = parse_jws_payload()
        if not payload:
            raise BadRequest('Invalid JWS payload')
        
        contact = payload.get('contact', [])
        email = None
        for c in contact:
            if c.startswith('mailto:'):
                email = c[7:]
                break
        
        # Create local account
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        account_id = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')
        
        try:
            cursor.execute(
                'INSERT INTO client_accounts (account_id, email) VALUES (?, ?)',
                (account_id, email or 'unknown@fake-acme.local')
            )
            conn.commit()
            status_code = 201
        except sqlite3.IntegrityError:
            status_code = 200
        
        conn.close()
        
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        account_url = f"{base_url}/acme/account/{account_id}"
        
        response = jsonify({
            'status': 'valid',
            'contact': contact,
            'orders': f"{account_url}/orders"
        })
        response.headers['Location'] = account_url
        
        return add_nonce_header(response), status_code
        
    except BadRequest:
        raise
    except Exception as e:
        logger.error(f"Error in new_account: {e}", exc_info=True)
        raise InternalServerError(f"Account creation failed: {str(e)}")

@app.route('/acme/new-order', methods=['GET', 'POST', 'HEAD'])
def new_order():
    """Create new certificate order - request from upstream"""
    try:
        if request.method in ['GET', 'HEAD']:
            response = Response('', status=204)
            return add_nonce_header(response)
        
        payload = parse_jws_payload()
        if not payload:
            raise BadRequest('Invalid JWS payload')
        
        identifiers = payload.get('identifiers', [])
        if not identifiers:
            raise BadRequest('No identifiers provided')
        
        domains = [ident['value'] for ident in identifiers if ident.get('type') == 'dns']
        if not domains:
            raise BadRequest('No DNS identifiers')
        
        logger.info(f"Requesting certificate from upstream for domains: {domains}")
        
        # Get upstream ACME client
        upstream_client, provider = get_upstream_acme_client()
        
        # Create CSR for upstream
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ])).sign(private_key, hashes.SHA256(), default_backend())
        
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        
        # Create order with upstream
        upstream_order = upstream_client.new_order(csr_pem)
        
        logger.info(f"Created upstream order with {len(upstream_order.authorizations)} authorizations")
        
        # Save order to database
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'INSERT INTO orders (upstream_order_url, domains, status) VALUES (?, ?, ?)',
            (upstream_order.uri, json.dumps(domains), 'pending')
        )
        order_id = cursor.lastrowid
        
        # Get challenges from upstream authorizations
        authz_urls = []
        challenge_list = []
        
        for authz_url in upstream_order.authorizations:
            # Fetch authorization from upstream
            authz = upstream_client._authzr_from_response(
                upstream_client._post_as_get(authz_url),
                uri=authz_url
            )
            
            domain = authz.body.identifier.value
            logger.info(f"Got authorization for domain: {domain}")
            
            # Save challenges
            for challenge in authz.body.challenges:
                cursor.execute(
                    'INSERT INTO challenges (order_id, domain, challenge_type, token, upstream_challenge_url, status) VALUES (?, ?, ?, ?, ?, ?)',
                    (order_id, domain, challenge.typ, challenge.token, challenge.uri, 'pending')
                )
                challenge_id = cursor.lastrowid
                challenge_list.append({
                    'id': challenge_id,
                    'type': challenge.typ,
                    'token': challenge.token,
                    'domain': domain
                })
            
            base_url = request.url_root.rstrip('/')
            if base_url.startswith('http://'):
                base_url = base_url.replace('http://', 'https://')
            
            authz_urls.append(f"{base_url}/acme/authz/{order_id}/{domain}")
        
        conn.commit()
        conn.close()
        
        # Build response
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        order_url = f"{base_url}/acme/order/{order_id}"
        
        response = jsonify({
            'status': 'pending',
            'expires': (datetime.now() + timedelta(days=7)).isoformat() + 'Z',
            'identifiers': identifiers,
            'authorizations': authz_urls,
            'finalize': f"{order_url}/finalize"
        })
        response.headers['Location'] = order_url
        
        logger.info(f"Created order {order_id} with {len(challenge_list)} challenges")
        
        return add_nonce_header(response), 201
        
    except BadRequest:
        raise
    except Exception as e:
        logger.error(f"Error creating order: {e}", exc_info=True)
        raise InternalServerError(f"Order creation failed: {str(e)}")

@app.route('/acme/authz/<int:order_id>/<domain>', methods=['GET', 'POST', 'HEAD'])
def get_authorization(order_id: int, domain: str):
    """Get authorization for domain"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get challenges for this domain and order
        cursor.execute(
            'SELECT id, challenge_type, token, status FROM challenges WHERE order_id = ? AND domain = ?',
            (order_id, domain)
        )
        challenges_data = cursor.fetchall()
        
        conn.close()
        
        if not challenges_data:
            raise NotFound('Authorization not found')
        
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        challenges_list = []
        for chal_id, chal_type, token, status in challenges_data:
            challenge_url = f"{base_url}/acme/challenge/{chal_id}"
            challenges_list.append({
                'type': chal_type,
                'url': challenge_url,
                'token': token,
                'status': status
            })
        
        response = jsonify({
            'status': 'pending',
            'expires': (datetime.now() + timedelta(days=7)).isoformat() + 'Z',
            'identifier': {
                'type': 'dns',
                'value': domain
            },
            'challenges': challenges_list
        })
        
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error getting authorization: {e}", exc_info=True)
        raise InternalServerError(str(e))

@app.route('/acme/challenge/<int:challenge_id>', methods=['GET', 'POST', 'HEAD'])
def respond_to_challenge(challenge_id: int):
    """Respond to challenge - notify upstream"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT order_id, domain, challenge_type, token, upstream_challenge_url, status FROM challenges WHERE id = ?',
            (challenge_id,)
        )
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            raise NotFound('Challenge not found')
        
        order_id, domain, chal_type, token, upstream_url, status = result
        
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        challenge_url = f"{base_url}/acme/challenge/{challenge_id}"
        authz_url = f"{base_url}/acme/authz/{order_id}/{domain}"
        
        # If POST, tell upstream we're ready for validation
        if request.method == 'POST':
            payload = parse_jws_payload()
            if payload is not None and status == 'pending':
                logger.info(f"Client ready for validation of {chal_type} challenge for {domain}")
                
                # Get upstream client
                upstream_client, provider = get_upstream_acme_client()
                
                # Tell upstream to validate (answer the challenge)
                try:
                    # Post empty body to upstream challenge URL to trigger validation
                    upstream_client._post_as_get(upstream_url)
                    logger.info(f"Notified {provider} to validate challenge")
                    
                    # Update status to processing
                    cursor.execute(
                        'UPDATE challenges SET status = ? WHERE id = ?',
                        ('processing', challenge_id)
                    )
                    conn.commit()
                    status = 'processing'
                    
                except Exception as e:
                    logger.error(f"Failed to notify upstream: {e}")
        
        conn.close()
        
        # Build response
        response_data = {
            'type': chal_type,
            'status': status,
            'url': challenge_url,
            'token': token
        }
        
        if status in ['valid', 'invalid']:
            response_data['validated'] = datetime.now().isoformat() + 'Z'
        
        response = jsonify(response_data)
        response.headers['Link'] = f'<{authz_url}>;rel="up"'
        
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error responding to challenge: {e}", exc_info=True)
        raise InternalServerError(str(e))

@app.route('/acme/order/<int:order_id>', methods=['GET', 'POST', 'HEAD'])
def get_order(order_id: int):
    """Get order status"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
        order = cursor.fetchone()
        
        if not order:
            conn.close()
            raise NotFound('Order not found')
        
        domains = json.loads(order[3])
        status = order[4]
        
        # Get authorization URLs
        cursor.execute('SELECT DISTINCT domain FROM challenges WHERE order_id = ?', (order_id,))
        auth_domains = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        order_url = f"{base_url}/acme/order/{order_id}"
        authz_urls = [f"{base_url}/acme/authz/{order_id}/{d}" for d in auth_domains]
        
        response = jsonify({
            'status': status,
            'expires': (datetime.now() + timedelta(days=7)).isoformat() + 'Z',
            'identifiers': [{'type': 'dns', 'value': d} for d in domains],
            'authorizations': authz_urls,
            'finalize': f"{order_url}/finalize",
            'certificate': f"{order_url}/certificate" if status == 'valid' else None
        })
        response.headers['Location'] = order_url
        
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error getting order: {e}", exc_info=True)
        raise InternalServerError(str(e))

@app.route('/acme/order/<int:order_id>/finalize', methods=['GET', 'POST', 'HEAD'])
def finalize_order(order_id: int):
    """Finalize order and get certificate from upstream"""
    try:
        if request.method in ['GET', 'HEAD']:
            response = Response('', status=200)
            return add_nonce_header(response)
        
        payload = parse_jws_payload()
        if not payload:
            raise BadRequest('Invalid JWS payload')
        
        csr = payload.get('csr')
        if not csr:
            raise BadRequest('CSR required')
        
        logger.info(f"Finalizing order {order_id}")
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT upstream_order_url FROM orders WHERE id = ?', (order_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            raise NotFound('Order not found')
        
        upstream_order_url = result[0]
        
        # Get upstream client
        upstream_client, provider = get_upstream_acme_client()
        
        # Finalize with upstream
        logger.info(f"Finalizing with {provider}...")
        
        # The upstream order should already be validated
        # Poll upstream order to get certificate
        try:
            # Get upstream order status
            upstream_order_obj = upstream_client._post_as_get(upstream_order_url)
            
            # If certificate is available, get it
            if hasattr(upstream_order_obj, 'body') and hasattr(upstream_order_obj.body, 'certificate'):
                cert_url = upstream_order_obj.body.certificate
                if cert_url:
                    logger.info(f"Downloading certificate from {provider}")
                    cert_response = upstream_client._post_as_get(cert_url)
                    certificate_pem = cert_response.text
                    
                    # Update order status
                    cursor.execute(
                        'UPDATE orders SET status = ? WHERE id = ?',
                        ('valid', order_id)
                    )
                    conn.commit()
                    
                    logger.info(f"✓ Got real certificate from {provider}!")
                else:
                    logger.warning("Certificate URL not available yet")
            else:
                logger.warning("Order not finalized yet on upstream")
        
        except Exception as e:
            logger.error(f"Failed to get certificate from upstream: {e}")
        
        conn.close()
        
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        order_url = f"{base_url}/acme/order/{order_id}"
        
        response = jsonify({
            'status': 'processing',
            'certificate': f"{order_url}/certificate"
        })
        response.headers['Location'] = order_url
        
        return add_nonce_header(response), 200
        
    except BadRequest:
        raise
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error finalizing order: {e}", exc_info=True)
        raise InternalServerError(str(e))

# User Management API
@app.route('/api/users', methods=['GET', 'POST'])
def users_api():
    """User management"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM users WHERE active = 1')
        results = cursor.fetchall()
        conn.close()
        return jsonify({'users': [
            {'id': r[0], 'username': r[1], 'email': r[2], 'created_at': r[3]}
            for r in results
        ]})
    
    # POST
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        raise BadRequest("username and email required")
    
    try:
        cursor.execute(
            'INSERT INTO users (username, email) VALUES (?, ?)',
            (data['username'], data['email'])
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return jsonify({'id': user_id, 'username': data['username'], 'email': data['email']}), 201
    except sqlite3.IntegrityError:
        conn.close()
        raise BadRequest("User already exists")

@app.route('/api/users/<username>', methods=['GET', 'DELETE'])
def user_detail(username):
    """Get or delete user"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if request.method == 'DELETE':
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        if deleted:
            return '', 204
        raise NotFound("User not found")
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({'id': result[0], 'username': result[1], 'email': result[2], 'created_at': result[3]})
    raise NotFound("User not found")

@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': os.path.exists(DATABASE_PATH)
    })

@app.route('/terms', methods=['GET'])
def terms():
    """Terms of Service"""
    return "<html><body><h1>ACME Gateway - Terms of Service</h1><p>This gateway forwards requests to upstream CAs.</p></body></html>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)