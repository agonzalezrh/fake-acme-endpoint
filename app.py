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

def parse_jws_payload():
    """Parse JWS-signed ACME request payload"""
    try:
        data = request.get_data(as_text=True)
        logger.debug(f"Received request data: {data[:200]}...")
        
        if not data:
            logger.warning("No request data")
            return None
        
        # Parse JWS envelope
        try:
            jws_data = json.loads(data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return None
        
        # Check if this is a JWS request
        if 'payload' not in jws_data:
            logger.debug("Not a JWS request, returning raw data")
            return jws_data
        
        # Decode payload (base64url encoded)
        payload_b64 = jws_data['payload']
        if not payload_b64:  # Empty payload for POST-as-GET
            logger.debug("Empty JWS payload (POST-as-GET)")
            return {}
        
        # Base64url decode (no padding needed for urlsafe_b64decode)
        try:
            # Add padding if needed
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += '=' * padding
            
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes.decode('utf-8'))
            
            logger.debug(f"Decoded JWS payload: {payload}")
            return payload
        except Exception as e:
            logger.error(f"Failed to decode JWS payload: {e}")
            return None
        
    except Exception as e:
        logger.error(f"Error parsing JWS payload: {e}", exc_info=True)
        return None

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
        
        # Migrate old database schema if needed
        try:
            # Check if old challenges table exists with wrong schema
            cursor.execute("PRAGMA table_info(challenges)")
            columns = [row[1] for row in cursor.fetchall()]
            
            if 'authz_id' not in columns and 'cert_id' in columns:
                # Drop old table and recreate
                logger.info("Migrating old challenges table schema...")
                cursor.execute('DROP TABLE IF EXISTS challenges')
                cursor.execute('''
                    CREATE TABLE challenges (
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
                logger.info("Challenges table migrated successfully")
            
            # Check if old certificates table exists with wrong schema
            cursor.execute("PRAGMA table_info(certificates)")
            cert_columns = [row[1] for row in cursor.fetchall()]
            
            if 'order_id' not in cert_columns and ('user_id' in cert_columns or 'cert_id' in cert_columns):
                # Drop old table and recreate
                logger.info("Migrating old certificates table schema...")
                cursor.execute('DROP TABLE IF EXISTS certificates')
                cursor.execute('''
                    CREATE TABLE certificates (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        order_id INTEGER,
                        cert_pem TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (order_id) REFERENCES orders (id)
                    )
                ''')
                logger.info("Certificates table migrated successfully")
        except Exception as e:
            logger.warning(f"Schema migration check failed: {e}")
        
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
            
        payload = parse_jws_payload()
        if payload is None:
            raise BadRequest('Invalid JWS payload')
        
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

@app.route('/acme/account/<int:account_id>', methods=['GET', 'POST', 'HEAD'])
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
            
        payload = parse_jws_payload()
        if payload is None:
            raise BadRequest('Invalid JWS payload')
        
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
            
            # Use HTTPS for authz URLs
            base_url_temp = request.url_root.rstrip('/')
            if base_url_temp.startswith('http://'):
                base_url_temp = base_url_temp.replace('http://', 'https://')
            authz_urls.append(f"{base_url_temp}/acme/authz/{authz_id}")
        
        conn.commit()
        conn.close()
        
        # Build base URL with HTTPS
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        # Generate order URL
        order_url = f"{base_url}/acme/order/{order_id}"
        
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

@app.route('/acme/order/<int:order_id>', methods=['GET', 'POST', 'HEAD'])
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

@app.route('/acme/authz/<int:authz_id>', methods=['GET', 'POST', 'HEAD'])
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
        
        # Build base URL with HTTPS
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        challenges_list = []
        for chal_id, chal_type, token, chal_status in challenges_data:
            challenge_url = f"{base_url}/acme/challenge/{chal_id}"
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

@app.route('/acme/challenge/<int:challenge_id>', methods=['GET', 'POST', 'HEAD'])
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
        
        authz_id = challenge[1]  # authz_id
        chal_type = challenge[2]  # type
        token = challenge[3]  # token
        current_status = challenge[4]  # status
        
        # Build URLs
        base_url = request.url_root.rstrip('/')
        if base_url.startswith('http://'):
            base_url = base_url.replace('http://', 'https://')
        
        challenge_url = f"{base_url}/acme/challenge/{challenge_id}"
        authz_url = f"{base_url}/acme/authz/{authz_id}"
        
        # For POST requests with empty payload, client is ready - start validation
        if request.method == 'POST':
            payload = parse_jws_payload()
            if payload is not None and current_status == 'pending':
                # For fake endpoint: auto-validate immediately
                # In production, this would trigger async validation
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE challenges SET status = ?, validated = ? WHERE id = ?',
                    ('valid', datetime.now().isoformat(), challenge_id)
                )
                cursor.execute(
                    'UPDATE authorizations SET status = ? WHERE id = ?',
                    ('valid', authz_id)
                )
                # Also update order status to ready
                cursor.execute(
                    'UPDATE orders SET status = ? WHERE id IN (SELECT order_id FROM authorizations WHERE id = ?)',
                    ('ready', authz_id)
                )
                conn.commit()
                conn.close()
                current_status = 'valid'
        
        # Build response
        response_data = {
            'type': chal_type,
            'status': current_status,
            'url': challenge_url,
            'token': token
        }
        
        # Add validated timestamp if challenge is valid
        if current_status in ['valid', 'invalid']:
            response_data['validated'] = datetime.now().isoformat() + 'Z'
        
        response = jsonify(response_data)
        
        # Add Link header pointing to authorization
        response.headers['Link'] = f'<{authz_url}>;rel="up"'
        
        return add_nonce_header(response)
        
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error responding to challenge: {e}")
        raise InternalServerError(f"Challenge response failed: {str(e)}")

@app.route('/acme/order/<int:order_id>/finalize', methods=['GET', 'POST', 'HEAD'])
def finalize_order(order_id: int):
    """Finalize order and issue certificate (RFC 8555 Section 7.4)"""
    try:
        payload = parse_jws_payload()
        if not payload:
            raise BadRequest('Invalid JWS payload')
        
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
        
        # Generate a fake certificate chain (in production, this would use the CSR)
        # Certificate + Intermediate CA (full chain required by certbot)
        fake_cert = """-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUdXWw69/gJhpeVUO/B1RN7MUHCd4wDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCVVMxFTATBgNVBAoMDEZha2UgQUNNRSBDQTEaMBgGA1UE
AwwRRmFrZSBBQ01FIFJvb3QgQ0EwHhcNMjUwOTMwMDkyMzAyWhcNMjUxMjI5MDky
MzAyWjA5MQswCQYDVQQGEwJVUzESMBAGA1UECgwJRmFrZSBBQ01FMRYwFAYDVQQD
DA0qLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
5rPPCh+xIT7TM3n4lShrsj2F8LFDpRR0yBXwt8ADBvbcVr3j53JFb3o5VrLsFwT8
qNFcCI2L7xUcG8iqCtZXkNSHXBb1iBozw+KKp7hKrxAJ575NFLodXdFHyzoLz8lZ
PB3E8gTDE/AI1iQj4iTyk+oqHV1Dnu2fB8dLEpYifqVA5rMVXH7tEZp9jp+3iodf
lwyHqCSYMKzyGJQeLncewmMacGATpafX2pjXsO3YcvYFxoi9algp4VIhBx/pnev3
i/yIgs+j1A3yPBb6ItzWEZokcl4CyIusemRkl+VGGI7H7hG+HhDv1UVD2NvyI8O3
1gSzGe3CHaQBNCzRN0IgzQIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3
DQEBCwUAA4IBAQB3h9T+nxGu8jZgb3MNOd60SRGhebpdR5EZn4oFdT1ML+6xWy8m
gV4ZozFzwBY3w64ee7XSQg4HayUCakOX34v115xj/K4NSLEZOkrPXkWfC5AnS0rS
gJfK9c4jrhY7loTruMhBJXQRZ7kwVuvfjX2TuJ9KUtrUX0sthhdfUF2J17ERuxQX
tnjPGAcT85saIGgCzJ6EEB3TUuHJjZGNg1kf7K09meTd/I5VBixOuBxoAKmP8vKa
QauJ0Rbbb7x7LhR1uReYvHHqGApn0e7CBVfRgwZOpq5tNPkJ10PiTchZwFxlIjtN
ys6zGKAHXYTwPVWSokEqr+5iddebur5bnAgU
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUKUbJ3QrUhim6ZkPtsw1nc2s6jsswDQYJKoZIhvcNAQEL
BQAwQDELMAkGA1UEBhMCVVMxFTATBgNVBAoMDEZha2UgQUNNRSBDQTEaMBgGA1UE
AwwRRmFrZSBBQ01FIFJvb3QgQ0EwHhcNMjUwOTMwMDkyMzAyWhcNMzUwOTI4MDky
MzAyWjBAMQswCQYDVQQGEwJVUzEVMBMGA1UECgwMRmFrZSBBQ01FIENBMRowGAYD
VQQDDBFGYWtlIEFDTUUgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAImsU5OVxgWrEdLEqtL4xaXJfUYZpMadacDTbYq6C1mEh8DeLUI6kgqF
at2gEPlJCJ3EqsxsdLgBbeTdYuXxI4s3xihl2LZQ0nIsG+4/MD5VEvGAmTIj5KFA
bAd5BnU1Q20UAQXYtmu2DM20QP2L4IWx+z99reT1v9K4KYrHAgZlimmZZfsxF+Sd
eYjtNZo4LhJa3YZh5UxY5+ewLBiE6iTgkYYK6UI4MFrHRWmFqD1/dA1RswoVDHPX
ca1htgD8EZ2mzWFEU8n3ol555k1UpGnf5V/RSdCXD2oI7rEP5qOsEMGuiy6/8M2w
+dMVc9AoL26C/bbA9pbNIPdlQ73ss2kCAwEAAaMTMBEwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAcRmUogFuKJ7eMeryiRGU6R2IAww1b5ImsQs6
HVFtp6f+DdVpKp9gKqhbrGSSvXeX7MzvTIOa0nT/dUrkgqAoeAB1tyKYQmXunGia
uog6HUvicZJC9HwEUOn6UikD4wD/RLtFVpmlpO6cBhtHLKFh2VUF8YpmMhUwOTJ7
aqHEgBsJOGFPTor10zIBYsuEaSZtjc4Bzut4a4ZBl55otzlAiCy/yIGAw1XHzYJi
IoCem0XFjeLTA0Voiqj9a4zyziGDZE47CG9pzwZVCg11JYC3LcogDHR1ZUJNpWoE
B6GEiP+K2UieNYzWWKajkkSB1R4S3AERAl2FsQrT1Xo3aiV01w==
-----END CERTIFICATE-----
"""
        
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

@app.route('/acme/order/<int:order_id>/certificate', methods=['GET', 'POST', 'HEAD'])
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
            'SELECT id, token FROM challenges WHERE token = ? AND type = ?',
            (token, 'http-01')
        )
        result = cursor.fetchone()
        
        if result:
            challenge_id = result[0]
            # Mark challenge as valid when accessed
            cursor.execute(
                'UPDATE challenges SET status = ?, validated = ? WHERE id = ?',
                ('valid', datetime.now().isoformat(), challenge_id)
            )
            # Update authorization status
            cursor.execute(
                'UPDATE authorizations SET status = ? WHERE id IN (SELECT authz_id FROM challenges WHERE id = ?)',
                ('valid', challenge_id)
            )
            conn.commit()
            conn.close()
            
            # Return the token as key authorization
            # In a real implementation, this would be token + thumbprint
            return token, 200, {'Content-Type': 'text/plain'}
        else:
            conn.close()
            raise NotFound('Challenge not found')
            
    except NotFound:
        raise
    except Exception as e:
        logger.error(f"Error in HTTP challenge: {e}")
        raise InternalServerError(f"HTTP challenge failed: {str(e)}")

@app.route('/acme/revoke-cert', methods=['GET', 'POST', 'HEAD'])
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

@app.route('/acme/key-change', methods=['GET', 'POST', 'HEAD'])
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