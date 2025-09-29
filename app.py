#!/usr/bin/env python3
"""
Fake ACME Endpoint Application for OpenShift 4
Provides a fake ACME endpoint with user management and upstream fallback
"""

import os
import json
import sqlite3
import logging
import hashlib
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError
import acme
import acme.client
import acme.messages
from acme import challenges
from acme.client import ClientNetwork
from acme.client import ClientV2
from acme import crypto_util
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import josepy as jose

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
ACME_DIRECTORY_URL = os.getenv('ACME_DIRECTORY_URL', 'https://acme-v02.api.letsencrypt.org/directory')
ZEROSSL_API_KEY = os.getenv('ZEROSSL_API_KEY')
LETSENCRYPT_FALLBACK = os.getenv('LETSENCRYPT_FALLBACK', 'true').lower() == 'true'
DATABASE_PATH = os.getenv('DATABASE_PATH', '/data/fake_acme.db')
CHALLENGE_PORT = int(os.getenv('CHALLENGE_PORT', '8080'))
DNS_CHALLENGE_DOMAIN = os.getenv('DNS_CHALLENGE_DOMAIN', 'acme-challenge.example.com')

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
        
        # Users table
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
        
        # Certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                domain TEXT NOT NULL,
                cert_pem TEXT,
                key_pem TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Challenges table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id INTEGER,
                type TEXT NOT NULL,
                token TEXT NOT NULL,
                key_authorization TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cert_id) REFERENCES certificates (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _init_upstream_clients(self):
        """Initialize upstream ACME clients"""
        try:
            # ZeroSSL client
            if ZEROSSL_API_KEY:
                self.upstream_clients['zerossl'] = {
                    'api_key': ZEROSSL_API_KEY,
                    'base_url': 'https://api.zerossl.com'
                }
            
            # Let's Encrypt client
            if LETSENCRYPT_FALLBACK:
                self.upstream_clients['letsencrypt'] = {
                    'directory_url': 'https://acme-v02.api.letsencrypt.org/directory'
                }
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
            raise ValueError(f"User {username} already exists")
        finally:
            conn.close()
    
    def delete_user(self, username: str) -> bool:
        """Delete a user and all associated certificates"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        try:
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            if not result:
                return False
            
            user_id = result[0]
            
            # Delete associated certificates and challenges
            cursor.execute('DELETE FROM challenges WHERE cert_id IN (SELECT id FROM certificates WHERE user_id = ?)', (user_id,))
            cursor.execute('DELETE FROM certificates WHERE user_id = ?', (user_id,))
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
                'created_at': result[3],
                'active': bool(result[4])
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
                    'created_at': row[3],
                    'active': bool(row[4])
                }
                for row in results
            ]
        finally:
            conn.close()

# Initialize the fake ACME provider
acme_provider = FakeACMEProvider()

@app.route('/acme/directory', methods=['GET'])
def acme_directory():
    """ACME directory endpoint"""
    base_url = request.url_root.rstrip('/')
    
    return jsonify({
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

@app.route('/acme/new-nonce', methods=['HEAD', 'GET'])
def new_nonce():
    """Generate new nonce"""
    nonce = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
    response = Response('', status=200)
    response.headers['Replay-Nonce'] = nonce
    return response

@app.route('/acme/new-account', methods=['POST'])
def new_account():
    """Create new ACME account"""
    try:
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        # Extract account information
        contact = payload.get('contact', [])
        email = None
        for contact_item in contact:
            if contact_item.startswith('mailto:'):
                email = contact_item[7:]  # Remove 'mailto:' prefix
                break
        
        if not email:
            raise BadRequest('Email contact required')
        
        # Create user account
        username = email.split('@')[0]
        user = acme_provider.create_user(username, email)
        
        # Generate account key
        account_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        account_key_pem = account_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Store account key (in real implementation, this should be encrypted)
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET account_key = ? WHERE id = ?',
            (account_key_pem.decode(), user['id'])
        )
        conn.commit()
        conn.close()
        
        # Generate account URL
        account_url = f"{request.url_root}acme/account/{user['id']}"
        
        response = jsonify({
            'status': 'valid',
            'contact': contact,
            'orders': f"{account_url}/orders"
        })
        response.headers['Location'] = account_url
        response.headers['Replay-Nonce'] = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
        
        return response, 201
        
    except Exception as e:
        logger.error(f"Error creating account: {e}")
        raise InternalServerError(f"Account creation failed: {str(e)}")

@app.route('/acme/new-order', methods=['POST'])
def new_order():
    """Create new certificate order"""
    try:
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
        
        # Create certificate order
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # For simplicity, use the first domain as primary
        primary_domain = domains[0]
        
        cursor.execute(
            'INSERT INTO certificates (domain, status) VALUES (?, ?)',
            (primary_domain, 'pending')
        )
        cert_id = cursor.lastrowid
        
        # Create challenges for each domain
        for domain in domains:
            # HTTP-01 challenge
            http_token = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
            cursor.execute(
                'INSERT INTO challenges (cert_id, type, token) VALUES (?, ?, ?)',
                (cert_id, 'http-01', http_token)
            )
            
            # DNS-01 challenge
            dns_token = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
            cursor.execute(
                'INSERT INTO challenges (cert_id, type, token) VALUES (?, ?, ?)',
                (cert_id, 'dns-01', dns_token)
            )
        
        conn.commit()
        conn.close()
        
        # Generate order URL
        order_url = f"{request.url_root}acme/order/{cert_id}"
        
        response = jsonify({
            'status': 'pending',
            'expires': (datetime.now() + timedelta(days=30)).isoformat(),
            'identifiers': identifiers,
            'authorizations': [f"{order_url}/auth/{i}" for i in range(len(domains))],
            'finalize': f"{order_url}/finalize"
        })
        response.headers['Location'] = order_url
        response.headers['Replay-Nonce'] = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
        
        return response, 201
        
    except Exception as e:
        logger.error(f"Error creating order: {e}")
        raise InternalServerError(f"Order creation failed: {str(e)}")

@app.route('/acme/order/<int:order_id>/auth/<int:auth_id>', methods=['GET'])
def get_authorization(order_id: int, auth_id: int):
    """Get authorization for domain"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('SELECT domain FROM certificates WHERE id = ?', (order_id,))
        result = cursor.fetchone()
        if not result:
            raise NotFound('Order not found')
        
        domain = result[0]
        
        # Get challenges
        cursor.execute(
            'SELECT type, token FROM challenges WHERE cert_id = ?',
            (order_id,)
        )
        challenges_data = cursor.fetchall()
        
        conn.close()
        
        challenges_list = []
        for challenge_type, token in challenges_data:
            challenge_url = f"{request.url_root}acme/challenge/{order_id}/{challenge_type}"
            challenges_list.append({
                'type': challenge_type,
                'url': challenge_url,
                'token': token
            })
        
        response = jsonify({
            'status': 'pending',
            'expires': (datetime.now() + timedelta(days=7)).isoformat(),
            'identifier': {
                'type': 'dns',
                'value': domain
            },
            'challenges': challenges_list
        })
        response.headers['Replay-Nonce'] = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
        
        return response
        
    except Exception as e:
        logger.error(f"Error getting authorization: {e}")
        raise InternalServerError(f"Authorization failed: {str(e)}")

@app.route('/acme/challenge/<int:order_id>/<challenge_type>', methods=['POST'])
def respond_to_challenge(order_id: int, challenge_type: str):
    """Respond to ACME challenge"""
    try:
        payload = request.get_json()
        if not payload:
            raise BadRequest('Invalid JSON payload')
        
        key_authorization = payload.get('keyAuthorization')
        if not key_authorization:
            raise BadRequest('keyAuthorization required')
        
        # Update challenge with key authorization
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE challenges SET key_authorization = ?, status = ? WHERE cert_id = ? AND type = ?',
            (key_authorization, 'valid', order_id, challenge_type)
        )
        
        conn.commit()
        conn.close()
        
        response = jsonify({
            'type': challenge_type,
            'status': 'valid',
            'url': f"{request.url_root}acme/challenge/{order_id}/{challenge_type}",
            'token': payload.get('token', ''),
            'keyAuthorization': key_authorization
        })
        response.headers['Replay-Nonce'] = base64.urlsafe_b64encode(os.urandom(32)).decode('ascii').rstrip('=')
        
        return response
        
    except Exception as e:
        logger.error(f"Error responding to challenge: {e}")
        raise InternalServerError(f"Challenge response failed: {str(e)}")

@app.route('/.well-known/acme-challenge/<token>', methods=['GET'])
def http_challenge(token: str):
    """HTTP-01 challenge endpoint"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT key_authorization FROM challenges WHERE token = ? AND type = ?',
            (token, 'http-01')
        )
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return result[0], 200, {'Content-Type': 'text/plain'}
        else:
            raise NotFound('Challenge not found')
            
    except Exception as e:
        logger.error(f"Error in HTTP challenge: {e}")
        raise InternalServerError(f"HTTP challenge failed: {str(e)}")

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
    except Exception as e:
        logger.error(f"Error getting user: {e}")
        raise InternalServerError(f"Failed to get user: {str(e)}")

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)