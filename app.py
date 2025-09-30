#!/usr/bin/env python3
"""
ACME Proxy for OpenShift 4
Proxies ACME requests to ZeroSSL with Let's Encrypt fallback
Returns REAL certificates from upstream providers
"""

import os
import json
import sqlite3
import logging
import base64
from datetime import datetime

import requests
from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
ZEROSSL_EAB_KID = os.getenv('ZEROSSL_EAB_KID')
ZEROSSL_EAB_HMAC_KEY = os.getenv('ZEROSSL_EAB_HMAC_KEY')
LETSENCRYPT_FALLBACK = os.getenv('LETSENCRYPT_FALLBACK', 'true').lower() == 'true'
DATABASE_PATH = os.getenv('DATABASE_PATH', '/data/fake_acme.db')

# Upstream ACME URLs  
ZEROSSL_BASE = 'https://acme.zerossl.com/v2/DV90'
LETSENCRYPT_BASE = 'https://acme-v02.api.letsencrypt.org/directory'

def get_upstream_base():
    """Get upstream provider base URL"""
    if ZEROSSL_EAB_KID and ZEROSSL_EAB_HMAC_KEY:
        return ZEROSSL_BASE, 'zerossl'
    if LETSENCRYPT_FALLBACK:
        return LETSENCRYPT_BASE, 'letsencrypt'
    return None, None

def proxy_request(upstream_path):
    """Proxy request to upstream ACME provider"""
    upstream_base, provider = get_upstream_base()
    if not upstream_base:
        raise InternalServerError("No upstream configured")
    
    # For directory requests, get the directory first
    if not upstream_path or upstream_path == 'directory':
        upstream_url = upstream_base
    else:
        # Get directory to find endpoint URLs
        try:
            dir_resp = requests.get(upstream_base, timeout=10)
            directory = dir_resp.json()
            
            # Map our paths to upstream paths
            path_map = {
                'new-nonce': directory.get('newNonce'),
                'new-account': directory.get('newAccount'),
                'new-order': directory.get('newOrder'),
                'revoke-cert': directory.get('revokeCert'),
                'key-change': directory.get('keyChange')
            }
            
            if upstream_path in path_map:
                upstream_url = path_map[upstream_path]
            else:
                # For dynamic paths like authz, challenge, order - construct from base
                upstream_url = upstream_base.replace('/directory', '') + '/' + upstream_path
                
        except Exception as e:
            logger.error(f"Failed to get directory: {e}")
            raise InternalServerError("Failed to contact upstream")
    
    # Proxy the request
    try:
        headers = {'Content-Type': request.headers.get('Content-Type', 'application/jose+json')}
        
        if request.method == 'POST':
            resp = requests.post(upstream_url, data=request.get_data(), headers=headers, timeout=30)
        elif request.method == 'GET':
            resp = requests.get(upstream_url, headers=headers, timeout=30)
        elif request.method == 'HEAD':
            resp = requests.head(upstream_url, headers=headers, timeout=30)
        else:
            raise BadRequest("Unsupported method")
        
        # Create response
        flask_resp = Response(resp.content, status=resp.status_code)
        flask_resp.headers['Content-Type'] = resp.headers.get('Content-Type', 'application/json')
        
        # Copy ACME headers
        for header in ['Replay-Nonce', 'Location', 'Link', 'Retry-After', 'Cache-Control']:
            if header in resp.headers:
                flask_resp.headers[header] = resp.headers[header]
        
        return flask_resp
        
    except requests.exceptions.Timeout:
        # Try fallback
        if provider == 'zerossl' and LETSENCRYPT_FALLBACK:
            logger.info("ZeroSSL timeout, trying Let's Encrypt")
            # Recursive call will use LE
            global ZEROSSL_EAB_KID
            ZEROSSL_EAB_KID = None
            try:
                return proxy_request(upstream_path)
            finally:
                ZEROSSL_EAB_KID = os.getenv('ZEROSSL_EAB_KID')
        raise InternalServerError("Upstream timeout")
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        raise InternalServerError(f"Proxy failed: {str(e)}")

# ACME endpoints
@app.route('/acme/directory', methods=['GET'])
def directory():
    return acme_directory()

@app.route('/acme/<path:path>', methods=['GET', 'POST', 'HEAD'])  
def acme_catchall(path):
    return proxy_request(path)

# User management (local, not proxied)
@app.route('/api/users', methods=['GET', 'POST'])
def users():
    if request.method == 'GET':
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE active = 1')
        results = cursor.fetchall()
        conn.close()
        return jsonify({'users': [{'id': r[0], 'username': r[1], 'email': r[2], 'created_at': r[3]} for r in results]})
    
    # POST
    data = request.get_json()
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, email) VALUES (?, ?)', (data['username'], data['email']))
        conn.commit()
        return jsonify({'id': cursor.lastrowid, 'username': data['username'], 'email': data['email']}), 201
    except sqlite3.IntegrityError:
        raise BadRequest("User exists")
    finally:
        conn.close()

@app.route('/api/users/<username>', methods=['GET', 'DELETE'])
def user_detail(username):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    if request.method == 'DELETE':
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        return '', 204
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({'id': result[0], 'username': result[1], 'email': result[2], 'created_at': result[3]})
    raise NotFound("User not found")

@app.route('/health', methods=['GET'])
def health():
    return health_check()

@app.route('/terms', methods=['GET'])
def terms():
    return terms_of_service()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)