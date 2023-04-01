import uwsgi  # noqa
import atexit
import base64
import os
import sys
import re
import time
import json
import _md5 as md5
import wsgiref.headers
import data_manager

print("startup")


def md5sum(data: str):
    m = md5.md5()
    m.update(data.encode())
    return m.hexdigest()


with open("config.json") as f:
    config = json.load(f)

if ".." in str(config):
    raise Exception("Potential path traversal attack in config.json. Remove all instances of '..' from the file.")


team: int = config["team"]
realm: str = f"Team {team}"
password: str = config["password"]
competition: str = config["competition"]

os.makedirs("schemes", exist_ok=True)
os.makedirs(os.path.join("saved_data", competition), exist_ok=True)

with open(os.path.join("schemes", competition+".json")) as f:
    scheme_data = json.load(f)

scheme = data_manager.Scheme(scheme_data)
print(scheme.creation_dict)
data_manager = data_manager.DataManager(competition, scheme)
try:
    with open(os.path.join("saved_data", competition, "data.json")) as f:
        data_manager.from_json(json.load(f))
except FileNotFoundError:
    print("No saved data found")
data_manager.update_all()  # ensure that all teams have the correct scheme


def calc_a1(user='test'):
    return md5sum('%s:%s:%s' % (user, realm, password))


def check_authorization(env, resp) -> str | bool | None:
    matches = re.compile(r'Digest \s+ (.*)', re.I + re.X).match(resp)
    if not matches:
        return None

    # print(matches)
    # print(matches.group(1))

    vals = re.compile(r', \s*', re.I + re.X).split(matches.group(1))

    d = {}

    # print(vals)

    pat = re.compile(r'(\S+?) \s* = \s* ("?) (.*) \2', re.X)
    for val in vals:
        ms = pat.match(val)
        if not ms:
            raise Exception(f'ERROR: no match between {val} and {pat}')
        d[ms.group(1)] = ms.group(3)

    # assert algorithm=='MD5', qop=='auth', ...
    # assert username=='test'?

    a1 = calc_a1(d['username'])
    a2 = md5sum('%s:%s' % (env['REQUEST_METHOD'], d['uri']))
    myresp = md5sum('%s:%s:%s:%s:%s:%s' % (a1, d['nonce'], d['nc'], d['cnonce'], d['qop'], a2))
    if myresp != d['response']:
        print("Auth failed!", file=sys.stderr)
        return None

    # check nonce's timestamp
    cur_nonce = int(time.time())
    aut_nonce = int(base64.b64decode(d['nonce']))
    if cur_nonce - aut_nonce > 10:  # 10sec
        print("Too old!", file=sys.stderr)
        return False

    return d['username']


def application(env, start_response):
    method, path, query = env['REQUEST_METHOD'], env['PATH_INFO'], env['QUERY_STRING']
    try:
        request_body_size = int(env.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0
    heads = wsgiref.headers.Headers([])
    authorization = env.get('HTTP_AUTHORIZATION', '')
    if method == "GET" and path == "/check_online":
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b"online"]
    state = check_authorization(env, authorization)
    if state:
        if method == "GET":
            if path == "/check_auth":
                # print("handling: ", env)
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return [b"authorized"]
            elif path == "/scheme.json":
                start_response('200 OK', [('Content-Type', 'application/json')])
                return [json.dumps(scheme_data).encode()]
            elif path == "/meta.json":
                start_response('200 OK', [('Content-Type', 'application/json')])
                return [json.dumps({
                    "scheme_version": md5sum(str(scheme_data)),
                    "competition": competition
                }).encode()]
            elif path == "/data.json":
                start_response('200 OK', [('Content-Type', 'application/json')])
                return [json.dumps(data_manager.to_json(net=True)).encode()]
        elif method == "POST":
            if path == "/update":
                request_body = env["wsgi.input"].read(request_body_size)
                update_json = json.loads(request_body)
                data_manager.update_from_net(update_json, state)
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return [b"updated"]
        start_response('404 Not Found', [('Content-Type', 'text/html')])
        return [b"404 Not Found"]

    nonce = base64.b64encode(str(int(time.time())).encode()).decode()
    auth_head = f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth,auth-int"'
    if state == False:  # noqa
        auth_head += ', stale=true'
    heads.add_header('WWW-Authenticate', auth_head)
    start_response('401 Authorization Required', heads.items())

    return [b'Awaiting authorization...']


def before_exit():
    print("Exit hook executing...")
    with open(os.path.join("saved_data", competition, "data.json"), "w") as f:
        json.dump(data_manager.to_json(), f)


atexit.register(before_exit)
