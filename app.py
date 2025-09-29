#!/usr/bin/env python3
"""
Fake ACME Endpoint Application for OpenShift 4
Provides a fake ACME endpoint with user management and upstream fallback
Implements RFC 8555 ACME protocol
"""

import os
import json
import sqlite3
import logging
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
ACME_DIRECTORY_URL = os.getenv('ACME_DIRECTORY_URL', 'https://acme-v02.api.letsencrypt.org/directory')
ZEROSSL_EAB_KID = os.getenv('ZEROSSL_EAB_KID')
ZEROSSL_EAB_HMAC_KEY = os.getenv('ZEROSSL_EAB_HMAC_KEY')
LETSENCRYPT_FALLBACK = os.getenv('LETSENCRYPT_FALLBACK', 'true').lower() == 'true'
DATABASE_PATH = os.getenv('DATABASE_PATH', '/data/fake_acme.db')
CHALLENGE_PORT = int(os.getenv('CHALLENGE_PORT', '8080'))
DNS_CHALLENGE_DOMAIN = os.getenv('DNS_CHALLENGE_DOMAIN', 'acme-challenge.example.com')

def add_nonce_header(response):
    """Add Replay-Nonce header to response"""
    nonce = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
    response.headers['Replay-Nonce'] = nonce
    response.headers['Cache-Control'] = 'no-store'
    return response

class FakeACMEProvider:
    """Fake ACME provider that manages users and certificates"""
    
    def __init__(self):
        self.init_database()
        self.upstream_clients = {}
        self._init_upstream_clients()
    
    def init_database(self):
        """Initialize SQLite database for persistent storage"""
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Users/Accounts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                account_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Orders table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                status TEXT DEFAULT 'pending',
                expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Authorizations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS authorizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER,
                domain TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders (id)
            )
        ''')
        
        # Challenges table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                authz_id INTEGER,
                type TEXT NOT NULL,
                token TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                validated TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (authz_id) REFERENCES authorizations (id)
            )
        ''')
        
        # Certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER,
                cert_pem TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _init_upstream_clients(self):
        """Initialize upstream ACME clients with EAB"""
        try:
            # ZeroSSL client with EAB
            if ZEROSSL_EAB_KID and ZEROSSL_EAB_HMAC_KEY:
                self.upstream_clients['zerossl'] = {
                    'eab_kid': ZEROSSL_EAB_KID,
                    'eab_hmac_key': ZEROSSL_EAB_HMAC_KEY,
                    'directory_url': 'https://acme.zerossl.com/v2/DV90'
                }
                logger.info("ZeroSSL upstream configured with EAB")
            
            # Let's Encrypt client (fallback)
            if LETSENCRYPT_FALLBACK:
                self.upstream_clients['letsencrypt'] = {
                    'directory_url': 'https://acme-v02.api.letsencrypt.org/directory'
                }
                logger.info("Let's Encrypt fallback enabled")
        except Exception as e:
            logger.error(f"Failed to initialize upstream clients: {e}")
    
    def create_user(self, username: str, email: str) -> Dict:
        """Create a new user"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, email) VALUES (?, ?)',
                (username, email)
            )
            user_id = cursor.lastrowid
            conn.commit()
            
            return {
                'id': user_id,
                'username': username,
                'email': email,
                'created_at': datetime.now().isoformat()
            }
        except sqlite3.IntegrityError:
            # User already exists, return existing user
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if result:
                return {
                    'id': result[0],
                    'username': result[1],
                    'email': result[2],
                    'created_at': result[4]
                }
            raise ValueError(f"User {username} already exists")
        finally:
            conn.close()
    
    def delete_user(self, username: str) -> bool:
        """Delete a user and all associated data"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if not result:
                return False
            
            user_id = result[0]
            
            # Delete all related data
            cursor.execute('DELETE FROM challenges WHERE authz_id IN (SELECT id FROM authorizations WHERE order_id IN (SELECT id FROM orders WHERE user_id = ?))', (user_id,))
            cursor.execute('DELETE FROM authorizations WHERE order_id IN (SELECT id FROM orders WHERE user_id = ?)', (user_id,))
            cursor.execute('DELETE FROM certificates WHERE order_id IN (SELECT id FROM orders WHERE user_id = ?)', (user_id,))
            cursor.execute('DELETE FROM orders WHERE user_id = ?', (user_id,))
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            
            conn.commit()
            return True
        finally:
            conn.close()
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Get user information"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if not result:
                return None
            
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'created_at': result[4],
                'active': bool(result[5])
            }
        finally:
            conn.close()
    
    def list_users(self) -> List[Dict]:
        """List all users"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM users WHERE active = 1')
            results = cursor.fetchall()
            
            return [
                {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'created_at': row[4],
                    'active': bool(row[5])
                }
                for row in results
            ]
        finally:
            conn.close()

# Initialize the fake ACME provider
acme_provider = FakeACMEProvider()

# ACME Protocol Endpoints

@app.route('/acme/directory', methods=['GET'])
def acme_directory():
    """ACME directory endpoint (RFC 8555 Section 7.1.1)"""
    # Always use HTTPS in directory URLs
    base_url = request.url_root.rstrip('/')
    if base_url.startswith('http://'):
        base_url = base_url.replace('http://', 'https://')
    
    response = jsonify({
        'newNonce': f'{base_url}/acme/new-nonce',
        'newAccount': f'{base_url}/acme/new-account',
        'newOrder': f'{base_url}/acme/new-order',
        'revokeCert': f'{base_url}/acme/revoke-cert',
        'keyChange': f'{base_url}/acme/key-change',
        'meta': {
            'termsOfService': f'{base_url}/terms',
            'website': f'{base_url}',
            'caaIdentities': ['fake-acme.example.com']
        }
    })
    return response

@app.route('/acme/new-nonce', methods=['HEAD', 'GET'])
def new_nonce():
    """Generate new nonce (RFC 8555 Section 7.2)"""
    response = Response('', status=200 if request.method == 'GET' else 204)
    return add_nonce_header(response)

@app.route('/acme/new-account', methods=['GET', 'POST', 'HEAD'])
def new_account():
    """Create or lookup ACME account (RFC 8555 Section 7.3)"""
    try:
        if request.method == 'HEAD':
            response = Response('', status=200)
            return add_nonce_header(response)
        
        if request.method == 'GET':
            # GET on new-account is not standard ACME, but handle it gracefully
            response = jsonify({'error': 'method not allowed', 'detail': 'Use POST to create or lookup account'})
            return add_nonce_header(response), 405
            
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        # Handle onlyReturnExisting for account lookup
        only_return_existing = payload.get('onlyReturnExisting', False)
        
        # Extract account information
        contact = payload.get('contact', [])
        email = None
        for contact_item in contact:
            if contact_item.startswith('mailto:'):
                email = contact_item[7:]
                break
        
        if not email and not only_return_existing:
            raise BadRequest('Email contact required')
        
        if only_return_existing:
            # Return existing account or 400 if not found
            if email:
                username = email.split('@')[0]
                user = acme_provider.get_user(username)
                if user:
                    account_url = f"{request.url_root}acme/account/{user['id']}"
                    response = jsonify({
                        'status': 'valid',
                        'contact': [f"mailto:{user['email']}"],
                        'orders': f"{account_url}/orders"
                    })
                    response.headers['Location'] = account_url
                    return add_nonce_header(response)
            raise BadRequest('Account does not exist')
        
        # Create user account
        username = email.split('@')[0]
        try:
            user = acme_provider.create_user(username, email)
            status_code = 201
        except ValueError:
            # Account already exists
            user = acme_provider.get_user(username)
            status_code = 200
        
        # Generate account URL
        account_url = f"{request.url_root}acme/account/{user['id']}"
        
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
        logger.error(f"Error in new_account: {e}")
        raise InternalServerError(f"Account operation failed: {str(e)}")

@app.route('/acme/account/<int:account_id>', methods=['POST'])
def account_details(account_id: int):
    """Get account details (RFC 8555 Section 7.3.2)"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (account_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            raise NotFound('Account not found')
        
        account_url = f"{request.url_root}acme/account/{account_id}"
        
        response = jsonify({
            'status': 'valid',
            'contact': [f"mailto:{result[2]}"],
            'orders': f"{account_url}/orders"
        })
        response.headers['Location'] = account_url
        
        return add_nonce_header(response)
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error getting account: {e}")
        raise InternalServerError(f"Account retrieval failed: {str(e)}")

@app.route('/acme/new-order', methods=['GET', 'POST', 'HEAD'])
def new_order():
    """Create new certificate order (RFC 8555 Section 7.4)"""
    try:
        if request.method == 'HEAD':
            response = Response('', status=200)
            return add_nonce_header(response)
        
        if request.method == 'GET':
            # GET on new-order is not standard ACME, but handle it gracefully
            response = jsonify({'error': 'method not allowed', 'detail': 'Use POST to create a new order'})
            return add_nonce_header(response), 405
            
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        identifiers = payload.get('identifiers', [])
        if not identifiers:
            raise BadRequest('No identifiers provided')
        
        # Extract domains
        domains = []
        for identifier in identifiers:
            if identifier.get('type') == 'dns':
                domains.append(identifier['value'])
        
        if not domains:
            raise BadRequest('No DNS identifiers provided')
        
        # Create order
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        expires = datetime.now() + timedelta(days=30)
        cursor.execute(
            'INSERT INTO orders (user_id, status, expires) VALUES (?, ?, ?)',
            (1, 'pending', expires.isoformat())  # Default user_id for now
        )
        order_id = cursor.lastrowid
        
        # Create authorizations for each domain
        authz_urls = []
        for domain in domains:
            cursor.execute(
                'INSERT INTO authorizations (order_id, domain, status, expires) VALUES (?, ?, ?, ?)',
                (order_id, domain, 'pending', expires.isoformat())
            )
            authz_id = cursor.lastrowid
            
            # Create challenges
            for challenge_type in ['http-01', 'dns-01']:
                token = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
                cursor.execute(
                    'INSERT INTO challenges (authz_id, type, token, status) VALUES (?, ?, ?, ?)',
                    (authz_id, challenge_type, token, 'pending')
                )
            
            authz_urls.append(f"{request.url_root}acme/authz/{authz_id}")
        
        conn.commit()
        conn.close()
        
        # Generate order URL
        order_url = f"{request.url_root}acme/order/{order_id}"
        
        response = jsonify({
            'status': 'pending',
            'expires': expires.isoformat() + 'Z',
            'identifiers': identifiers,
            'authorizations': authz_urls,
            'finalize': f"{order_url}/finalize"
        })
        response.headers['Location'] = order_url
        
        return add_nonce_header(response), 201
        
    except BadRequest:
        raise
    except Exception as e:
        logger.error(f"Error creating order: {e}")
        raise InternalServerError(f"Order creation failed: {str(e)}")

@app.route('/acme/order/<int:order_id>', methods=['POST'])
def get_order(order_id: int):
    """Get order status (RFC 8555 Section 7.4)"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
        order = cursor.fetchone()
        if not order:
            conn.close()
            raise NotFound('Order not found')
        
        # Get authorizations
        cursor.execute('SELECT id FROM authorizations WHERE order_id = ?', (order_id,))
        authz_ids = [row[0] for row in cursor.fetchall()]
        
        # Get identifiers
        cursor.execute('SELECT domain FROM authorizations WHERE order_id = ?', (order_id,))
        domains = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
        order_url = f"{request.url_root}acme/order/{order_id}"
        
        response = jsonify({
            'status': order[2],  # status
            'expires': order[3] + 'Z' if order[3] else None,
            'identifiers': [{'type': 'dns', 'value': d} for d in domains],
            'authorizations': [f"{request.url_root}acme/authz/{aid}" for aid in authz_ids],
            'finalize': f"{order_url}/finalize",
            'certificate': f"{order_url}/certificate" if order[2] == 'valid' else None
        })
        response.headers['Location'] = order_url
        
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error getting order: {e}")
        raise InternalServerError(f"Order retrieval failed: {str(e)}")

@app.route('/acme/authz/<int:authz_id>', methods=['POST'])
def get_authorization(authz_id: int):
    """Get authorization (RFC 8555 Section 7.5)"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM authorizations WHERE id = ?', (authz_id,))
        authz = cursor.fetchone()
        if not authz:
            conn.close()
            raise NotFound('Authorization not found')
        
        domain = authz[2]
        status = authz[3]
        expires = authz[4]
        
        # Get challenges
        cursor.execute('SELECT id, type, token, status FROM challenges WHERE authz_id = ?', (authz_id,))
        challenges_data = cursor.fetchall()
        
        conn.close()
        
        challenges_list = []
        for chal_id, chal_type, token, chal_status in challenges_data:
            challenge_url = f"{request.url_root}acme/challenge/{chal_id}"
            challenges_list.append({
                'type': chal_type,
                'url': challenge_url,
                'status': chal_status,
                'token': token
            })
        
        response = jsonify({
            'status': status,
            'expires': expires + 'Z' if expires else None,
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
        logger.error(f"Error getting authorization: {e}")
        raise InternalServerError(f"Authorization retrieval failed: {str(e)}")

@app.route('/acme/challenge/<int:challenge_id>', methods=['POST'])
def respond_to_challenge(challenge_id: int):
    """Respond to ACME challenge (RFC 8555 Section 7.5.1)"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,))
        challenge = cursor.fetchone()
        if not challenge:
            conn.close()
            raise NotFound('Challenge not found')
        
        # Auto-validate the challenge (this is a fake endpoint)
        cursor.execute(
            'UPDATE challenges SET status = ?, validated = ? WHERE id = ?',
            ('valid', datetime.now().isoformat(), challenge_id)
        )
        
        # Update authorization status
        cursor.execute(
            'UPDATE authorizations SET status = ? WHERE id = ?',
            ('valid', challenge[1])  # authz_id
        )
        
        conn.commit()
        conn.close()
        
        challenge_url = f"{request.url_root}acme/challenge/{challenge_id}"
        
        response = jsonify({
            'type': challenge[2],  # type
            'status': 'valid',
            'url': challenge_url,
            'token': challenge[3],  # token
            'validated': datetime.now().isoformat() + 'Z'
        })
        
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error responding to challenge: {e}")
        raise InternalServerError(f"Challenge response failed: {str(e)}")

@app.route('/acme/order/<int:order_id>/finalize', methods=['POST'])
def finalize_order(order_id: int):
    """Finalize order and issue certificate (RFC 8555 Section 7.4)"""
    try:
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        csr = payload.get('csr')
        if not csr:
            raise BadRequest('CSR required')
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Check if all authorizations are valid
        cursor.execute(
            'SELECT COUNT(*) FROM authorizations WHERE order_id = ? AND status != ?',
            (order_id, 'valid')
        )
        invalid_count = cursor.fetchone()[0]
        
        if invalid_count > 0:
            conn.close()
            raise BadRequest('Not all authorizations are valid')
        
        # Generate a fake certificate (in production, this would use the CSR)
        fake_cert = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAw8VK9qHN0I7RqZvsm4FqJ9EqNqVGLmKNMxDzELJPXqKqKqKqKqKqKqKq
-----END CERTIFICATE-----"""
        
        # Update order status
        cursor.execute(
            'UPDATE orders SET status = ? WHERE id = ?',
            ('valid', order_id)
        )
        
        # Store certificate
        cursor.execute(
            'INSERT INTO certificates (order_id, cert_pem) VALUES (?, ?)',
            (order_id, fake_cert)
        )
        
        conn.commit()
        conn.close()
        
        order_url = f"{request.url_root}acme/order/{order_id}"
        
        response = jsonify({
            'status': 'valid',
            'certificate': f"{order_url}/certificate"
        })
        response.headers['Location'] = order_url
        
        return add_nonce_header(response), 200
        
    except BadRequest:
        raise
    except Exception as e:
        logger.error(f"Error finalizing order: {e}")
        raise InternalServerError(f"Order finalization failed: {str(e)}")

@app.route('/acme/order/<int:order_id>/certificate', methods=['POST'])
def download_certificate(order_id: int):
    """Download certificate (RFC 8555 Section 7.4.2)"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT cert_pem FROM certificates WHERE order_id = ?', (order_id,))
        result = cursor.fetchone()
        
        conn.close()
        
        if not result:
            raise NotFound('Certificate not found')
        
        response = Response(result[0], status=200, content_type='application/pem-certificate-chain')
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error downloading certificate: {e}")
        raise InternalServerError(f"Certificate download failed: {str(e)}")

@app.route('/.well-known/acme-challenge/<token>', methods=['GET'])
def http_challenge(token: str):
    """HTTP-01 challenge endpoint (RFC 8555 Section 8.3)"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT token FROM challenges WHERE token = ? AND type = ?',
            (token, 'http-01')
        )
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            # Return the token as key authorization
            # In a real implementation, this would be token + thumbprint
            return token, 200, {'Content-Type': 'text/plain'}
        else:
            raise NotFound('Challenge not found')
            
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error in HTTP challenge: {e}")
        raise InternalServerError(f"HTTP challenge failed: {str(e)}")

@app.route('/acme/revoke-cert', methods=['POST'])
def revoke_cert():
    """Revoke certificate (RFC 8555 Section 7.6)"""
    try:
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        # In a real implementation, this would revoke the certificate
        response = jsonify({'status': 'revoked'})
        return add_nonce_header(response), 200
        
    except Exception as e:
        logger.error(f"Error revoking certificate: {e}")
        raise InternalServerError(f"Certificate revocation failed: {str(e)}")

@app.route('/acme/key-change', methods=['POST'])
def key_change():
    """Change account key (RFC 8555 Section 7.3.5)"""
    try:
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        # In a real implementation, this would change the account key
        response = jsonify({'status': 'ok'})
        return add_nonce_header(response), 200
        
    except Exception as e:
        logger.error(f"Error changing key: {e}")
        raise InternalServerError(f"Key change failed: {str(e)}")

# User Management API

@app.route('/api/users', methods=['GET'])
def list_users():
    """List all users"""
    try:
        users = acme_provider.list_users()
        return jsonify({'users': users})
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise InternalServerError(f"Failed to list users: {str(e)}")

@app.route('/api/users', methods=['POST'])
def create_user():
    """Create a new user"""
    try:
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        username = payload.get('username')
        email = payload.get('email')
        
        if not username or not email:
            raise BadRequest('username and email are required')
        
        user = acme_provider.create_user(username, email)
        return jsonify(user), 201
        
    except ValueError as e:
        raise BadRequest(str(e))
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise InternalServerError(f"Failed to create user: {str(e)}")

@app.route('/api/users/<username>', methods=['DELETE'])
def delete_user(username: str):
    """Delete a user"""
    try:
        success = acme_provider.delete_user(username)
        if success:
            return '', 204
        else:
            raise NotFound('User not found')
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise InternalServerError(f"Failed to delete user: {str(e)}")

@app.route('/api/users/<username>', methods=['GET'])
def get_user(username: str):
    """Get user information"""
    try:
        user = acme_provider.get_user(username)
        if user:
            return jsonify(user)
        else:
            raise NotFound('User not found')
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        raise InternalServerError(f"Failed to get user: {str(e)}")

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': os.path.exists(DATABASE_PATH),
        'upstream': {
            'zerossl': bool(ZEROSSL_EAB_KID and ZEROSSL_EAB_HMAC_KEY),
            'letsencrypt': LETSENCRYPT_FALLBACK
        }
    })

@app.route('/terms', methods=['GET'])
def terms_of_service():
    """Terms of Service"""
    return """
    <html>
    <head><title>Terms of Service</title></head>
    <body>
    <h1>Fake ACME Endpoint - Terms of Service</h1>
    <p>This is a fake ACME endpoint for testing purposes.</p>
    <p>By using this service, you agree that this is for testing only.</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)