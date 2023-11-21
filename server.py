# pip3 install requests-toolbelt
# in reference to images, hashes are actually v4 uuids
import threading

from requests_toolbelt import MultipartDecoder
import uwsgi  # noqa
import atexit
import base64
import os
import sys
import time
import json
import wsgiref.headers
import data_manager
import re
import hashlib
import hmac
import tbaapiv3client

print("startup")


class TeamData:
    def __init__(self, team_key: str):
        self.team_number = int(team_key.replace("frc", ""))
        self.team_key = team_key
        self.wins = 0
        self.ties = 0
        self.losses = 0

    def __repr__(self) -> str:
        return f"{self.team_number} w-l-t: {self.wins}-{self.losses}-{self.ties}"


class MatchScoreResult:
    def __init__(self):
        self.red_keys: list[str] = []
        self.blue_keys: list[str] = []
        self.winner: str = ""
        self.has_score = False

    def red_won(self):
        return self.winner == "red" and self.has_score

    def blue_won(self):
        return self.winner == "blue" and self.has_score

    def tied(self):
        return (self.winner != "red" and self.winner != "blue") and self.has_score


# match id : MatchScoreResult
scores_mutex = threading.Lock()
match_scores: dict[str, MatchScoreResult] = {}
team_scores: dict[str, TeamData] = {}


def calculate_team_scores():
    """
    Calculates the scores for each team based on the match scores
    MUST be called with scores_mutex held
    """
    team_scores.clear()
    for match_id, match_score in match_scores.items():
        if not match_score.has_score:
            continue

        for team_key in match_score.red_keys:
            if team_key not in team_scores:
                team_scores[team_key] = TeamData(team_key)
            team = team_scores[team_key]
            if match_score.red_won():
                team.wins += 1
            elif match_score.blue_won():
                team.losses += 1
            elif match_score.tied():
                team.ties += 1

        for team_key in match_score.blue_keys:
            if team_key not in team_scores:
                team_scores[team_key] = TeamData(team_key)
            team = team_scores[team_key]
            if match_score.blue_won():
                team.wins += 1
            elif match_score.red_won():
                team.losses += 1
            elif match_score.tied():
                team.ties += 1

    with open("score_summary.txt", "w") as score_summary:
        for team_key, team in team_scores.items():
            score_summary.write(f"{team_key}: {team.wins}-{team.losses}-{team.ties}\n")


def md5sum(data: str):
    return hashlib.md5(data.encode()).hexdigest()


with open("config.json") as f:
    config = json.load(f)

if ".." in str(config):
    raise Exception("Potential path traversal attack in config.json. Remove all instances of '..' from the file.")


team: int = config["team"]
realm: str = f"Team {team}"
password: str = config["password"]
competition: str = config["competition"]
tba_secret: str = config['tba_webhook_secret']

# only include qualifying matches (no semifinals, finals, etc.)
INTERESTING_LEVELS = ['qm']

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


def update_thread():
    configuration = tbaapiv3client.Configuration(
        host="https://www.thebluealliance.com/api/v3",
        api_key={
            'X-TBA-Auth-Key': config["tba_api_key"]
        }
    )
    with tbaapiv3client.ApiClient(configuration) as client:
        evt_key: str = config["event_key"]
        event_api = tbaapiv3client.EventApi(client)
        while True:
            print("[update_thread] Updating match scores...")
            try:
                match_data: list[tbaapiv3client.Match] = event_api.get_event_matches(evt_key)
                print("[update_thread] Got match data")
                print("[update_thread] Waiting for scores_mutex")
                with scores_mutex:
                    print("[update_thread] Got scores_mutex")
                    for match in match_data:
                        if match.comp_level in INTERESTING_LEVELS:
                            red: tbaapiv3client.MatchAlliance = match.alliances.red
                            blue: tbaapiv3client.MatchAlliance = match.alliances.blue

                            if red.score is None or blue.score is None or red.score == -1 or blue.score == -1:
                                continue

                            if match.key not in match_scores:
                                match_scores[match.key] = MatchScoreResult()

                            match_score: MatchScoreResult = match_scores[match.key]
                            match_score.has_score = True
                            match_score.red_keys = red.team_keys
                            match_score.blue_keys = blue.team_keys
                            match_score.winner = match.winning_alliance
                    print("[update_thread] Re-calculating team scores...")
                    calculate_team_scores()
                    print("[update_thread] Done updating match scores (released mutex)")
            except Exception as e:
                print("[update_thread] Error updating match scores:")
                print(e)
            time.sleep(60 * 5)  # only poll the TBA API once every 5 minutes


t = threading.Thread(target=update_thread, daemon=True)
t.start()
print("started match data update thread")


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
    if path.startswith("/match_data"):
        path = path.removeprefix("/match_data")
        if path == "/score_summary.txt":
            with open("score_summary.txt") as score_summary:
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return [score_summary.read().encode('utf-8')]
        if path == "/webhook":
            if method != "POST":
                start_response('405 Method Not Allowed', [('Content-Type', 'text/plain')])
                return [b'Only POST requests are allowed']
            request_body = env["wsgi.input"].read(request_body_size)
            print(f"\t`{request_body=}`")
            x_tba_hmac = env.get("HTTP_X_TBA_HMAC", "")
            if x_tba_hmac == "":
                start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                return [b'X-TBA-HMAC header missing']
            expected_hmac = hmac.new(tba_secret.encode("utf-8"), request_body, hashlib.sha256).hexdigest()
            if x_tba_hmac.lower() != expected_hmac.lower():
                print("Incorrect HMAC!")
                start_response('400 Bad Request', [('Content-Type', 'text/plain')])
                return [b'X-TBA-HMAC header incorrect']

            try:
                request_body_json: dict[str, ...] = json.loads(request_body)
            except json.JSONDecodeError:
                request_body_json: dict[str, ...] = {}

            if "message_type" not in request_body_json:
                request_body_json["message_type"] = "unknown"

            if request_body_json["message_type"] == "verification":
                print("\n\n\n\n")
                print("Received a webhook verification request:")
                print("\t", request_body_json["message_data"]["verification_key"])
                print("\n\n\n\n")
                start_response('200 OK', [('Content-Type', 'text/plain')])
                return [b'Asking a human to verify...']
            elif request_body_json["message_type"] == "ping":
                data: dict[str, str] = request_body_json["message_data"]
                print(f"Got a ping with title: {data['title']} and desc: {data['description']}")
            elif request_body_json["message_type"] == "match_score":
                data: dict[str, ...] = request_body_json["message_data"]
                match_data: dict[str, ...] = data["match"]
                match: tbaapiv3client.Match = tbaapiv3client.Match(**match_data)
                print(f"Got a match score update for {match.key}")
                if match.comp_level in INTERESTING_LEVELS:
                    with scores_mutex:
                        if match.key not in match_scores:
                            match_scores[match.key] = MatchScoreResult()

                        match_score: MatchScoreResult = match_scores[match.key]

                        red: tbaapiv3client.MatchAlliance = match.alliances.red
                        blue: tbaapiv3client.MatchAlliance = match.alliances.blue

                        match_score.red_keys = red.team_keys
                        match_score.blue_keys = blue.team_keys
                        match_score.winner = match.winning_alliance
                        if red.score is None or blue.score is None or red.score == -1 or blue.score == -1:
                            match_score.has_score = False
                        else:
                            match_score.has_score = True
                        calculate_team_scores()

            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [b'This is a webhook. It is not meant to be accessed by a human.']

        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'Testing server hello world...']

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
