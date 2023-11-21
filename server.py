# pip3 install requests-toolbelt
# in reference to images, hashes are actually v4 uuids
from requests_toolbelt import MultipartDecoder
import uwsgi  # noqa
import atexit
import base64
import os
import sys
import time
import json
import _md5 as md5
import wsgiref.headers
import data_manager
import re

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
os.makedirs(os.path.join("saved_data", competition, "images"), exist_ok=True)

with open(os.path.join("schemes", competition+".json")) as f:
    scheme_data = json.load(f)

scheme = data_manager.Scheme(scheme_data)
print(scheme.creation_dict)
data_mngr = data_manager.DataManager(competition, scheme)
try:
    with open(os.path.join("saved_data", competition, "data.json")) as f:
        data_mngr.from_json(json.load(f))
except FileNotFoundError:
    print("No saved data found")
try:
    with open(os.path.join("saved_data", competition, "images", "data.json")) as f:
        data_mngr.image_data_from_json(json.load(f))
except FileNotFoundError:
    print("No saved image data found")
data_mngr.update_all()  # ensure that all teams have the correct scheme


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
    method: str
    path: str
    query: str
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
                    "competition": competition,
                    "team": team,
                }).encode()]
            elif path == "/data.json":
                start_response('200 OK', [('Content-Type', 'application/json')])
                return [json.dumps(data_mngr.to_json(net=True, username=state)).encode()]
            elif path.startswith("/image/"):
                hsh = path.replace("/image/", "")
                if data_manager.verify_hash(hsh) and hsh in data_mngr.image_data:  # this is to protect from directory traversal
                    file_path = os.path.join("saved_data", competition, "images", hsh[:2], f"{hsh}.jpg")
                    if not os.path.exists(file_path):
                        file_path = os.path.join("saved_data", competition, "fallback.jpg")
                        if not os.path.exists(file_path):
                            file_path = "fallback.jpg"
                    start_response('200 OK', [('Content-Type', 'image/jpg')])
                    with open(file_path, 'rb') as img_file:
                        return [img_file.read()]
                start_response('404 Not Found', [('Content-Type', 'text/plain')])
                return [b"Bad hash"]
            elif path == "/image_hashes.txt":
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return ["\n".join(data_mngr.image_data.keys()).encode()]
            elif path.startswith('/image_meta/'):
                hsh = path.replace("/image_meta/", "")
                if data_manager.verify_hash(hsh) and hsh in data_mngr.image_data:  # this is to protect from directory traversal
                    start_response('200 OK', [('Content-Type', 'application/json')])
                    return [json.dumps(data_mngr.image_data[hsh]).encode()]
                start_response('404 Not Found', [('Content-Type', 'text/plain')])
                return [b"404 Not Found"]
        elif method == "POST":
            if path == "/update":
                request_body = env["wsgi.input"].read(request_body_size)
                update_json = json.loads(request_body)
                data_mngr.update_from_net(update_json, state)
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return [b"updated"]
            elif path == "/image_upload":
                print("\n\nBefore reading\n\n")
                # wsgi.file_wrapper
                request_body = env["wsgi.input"].read(request_body_size)
                """fields = {}
                files = {}
                def on_field(field):
                    fields[field.field_name] = field.value
                def on_file(file):
                    files[file.field_name] = {'name': file.file_name, 'file_object': file.file_object}
                multipart.parse_form(
                    {'Content-Type': env['CONTENT_TYPE'], 'Content-Length': env['CONTENT_LENGTH']},
                    env['wsgi.input'],
                    on_field,
                    on_file
                )
                print("\n\nImage upload:")
                print('fields: ', fields)
                print('files: ', files)
                print("\n\n")"""
                # print(f"Image upload body: {request_body}")
                decoder = MultipartDecoder(request_body, env["CONTENT_TYPE"])
                data = {}
                for part in decoder.parts:
                    name = re.match(r"form-data; name=\"(\w+)\"", part.headers[b'content-disposition'].decode()).groups()[0]
                    # print(name, part.content)
                    data[name] = part.content
                start_response('200 OK', [('Content-Type', 'text/plain')])
                try:
                    tags_ = json.loads(data['tags'].decode())
                    hsh_ = data['uuid'].decode()
                    team_ = int(data['team'].decode())
                    image_ = data['image']
                    path_ = data_mngr.image_path(hsh_)
                except: # noqa
                    return [b"failure"]
                data_mngr.image_data[hsh_] = {
                    "author": state,
                    "tags": tags_,
                    "team": team_,
                    "uuid": hsh_,
                }
                os.makedirs(os.path.dirname(path_), exist_ok=True)
                with open(path_, "wb") as f:
                    f.write(image_)
                
                return [b"uploaded"]
        start_response('404 Not Found', [('Content-Type', 'text/html')])
        return [b"404 Not Found"]
    else:
        if method == "POST" and path == "/image_upload":
            print("\n\nOh no, 401 upload\n\n")
            request_body = env["wsgi.input"].read(request_body_size)
            print("\n\nRead request input to be safe\n\n")
        else:
            print(f"method: {method}, path: {path}")

    nonce = base64.b64encode(str(int(time.time())).encode()).decode()
    auth_head = f'Digest realm="{realm}", nonce="{nonce}", algorithm=MD5, qop="auth,auth-int"'
    if state == False:  # noqa
        auth_head += ', stale=true'
    heads.add_header('WWW-Authenticate', auth_head)
    start_response('401 Authorization Required', heads.items())

    return [b'Awaiting authorization...']


def before_exit():
    print("Exit hook executing...")
    save_data()


def save_data():
    print("Saving data...")
    with open(os.path.join("saved_data", competition, "data.json"), "w") as f:
        json.dump(data_mngr.to_json(), f, indent=2)
    with open(os.path.join("saved_data", competition, "images", "data.json"), "w") as f:
        json.dump(data_mngr.image_data_to_json(), f, indent=2)
    print("Saved.")


def signal_save_data(signal_id):
    save_data()


uwsgi.register_signal(17, "worker", signal_save_data)  # register signal 17 handler
uwsgi.add_file_monitor(17, "./autosave.txt")  # send signal 17 on file change
uwsgi.add_timer(17, 60)  # send signal 17 every minute


atexit.register(before_exit)
