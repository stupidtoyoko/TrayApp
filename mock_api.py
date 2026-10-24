#!/usr/bin/env python3
"""Local-only mock API for TrayService development. NOT for production."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json, secrets, time, datetime
HOST, PORT = "127.0.0.1", 8765
USERS = {"demo": "demo123"}
SESSIONS = {}  # access -> {user, refresh}; refresh -> user
LICENSES = {}  # user -> expiry ISO date

def expiry_date(days=30):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).date().isoformat()

class Handler(BaseHTTPRequestHandler):
    server_version = "TrayAppMockAPI/1.0"
    def log_message(self, fmt, *args): print("%s - %s" % (self.address_string(), fmt % args))
    def send_json(self, status, data):
        raw=json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def read_json(self):
        try: return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0')) or 0).decode('utf-8'))
        except Exception: return {}
    def authorized_user(self):
        auth=self.headers.get('Authorization','')
        token=auth[7:] if auth.startswith('Bearer ') else ''
        return SESSIONS.get(token,{}).get('user')
    def do_POST(self):
        data=self.read_json()
        if self.path == '/api/auth/login':
            u,p=data.get('username',''),data.get('password','')
            if USERS.get(u) != p: return self.send_json(401, {'error':'invalid_credentials','message':'Неверный логин или пароль'})
            access='test_access_'+secrets.token_urlsafe(18); refresh='test_refresh_'+secrets.token_urlsafe(18)
            SESSIONS[access]={'user':u,'refresh':refresh}; SESSIONS['refresh:'+refresh]={'user':u}
            return self.send_json(200, {'access_token':access,'refresh_token':refresh,'token_type':'Bearer','expires_in':120,'username':u})
        if self.path == '/api/auth/refresh':
            refresh=data.get('refresh_token',''); session=SESSIONS.get('refresh:'+refresh)
            if not session: return self.send_json(401, {'error':'invalid_refresh_token'})
            user=session['user']; access='test_access_'+secrets.token_urlsafe(18); new_refresh='test_refresh_'+secrets.token_urlsafe(18)
            SESSIONS[access]={'user':user,'refresh':new_refresh}; SESSIONS['refresh:'+new_refresh]={'user':user}
            return self.send_json(200, {'access_token':access,'refresh_token':new_refresh,'expires_in':120})
        if self.path == '/api/license/status':
            user=self.authorized_user()
            if not user: return self.send_json(401, {'error':'unauthorized'})
            exp=LICENSES.get(user)
            if not exp: return self.send_json(200, {'has_license':False,'ticket':'','expires_at':'','ticket_ttl_seconds':60})
            return self.send_json(200, {'has_license':True,'ticket':'TEST_TICKET_'+user+'_'+exp,'expires_at':exp,'ticket_ttl_seconds':60})
        if self.path == '/api/license/activate':
            user=self.authorized_user()
            if not user: return self.send_json(401, {'error':'unauthorized'})
            if data.get('activation_code') != 'TEST-2026': return self.send_json(400, {'error':'invalid_activation_code','message':'Неверный тестовый код'})
            exp=expiry_date(30); LICENSES[user]=exp
            return self.send_json(200, {'ticket':'TEST_TICKET_'+user+'_'+exp,'expires_at':exp,'ticket_ttl_seconds':60})
        return self.send_json(404, {'error':'not_found','path':self.path})
    def do_GET(self):
        if self.path == '/health': return self.send_json(200, {'status':'ok','mode':'local-test-only'})
        return self.send_json(404, {'error':'not_found'})

if __name__ == '__main__':
    print(f'Локальный тестовый API: http://{HOST}:{PORT}')
    print('Тестовый вход: demo / demo123; код активации: TEST-2026')
    print('Только локальная разработка. Не используйте в production.')
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
