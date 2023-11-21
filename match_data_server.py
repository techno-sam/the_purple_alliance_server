# pip3 install requests-toolbelt
# in reference to images, hashes are actually v4 uuids
import pprint
import threading

import uwsgi  # noqa
import time
import json
import wsgiref.headers
import hashlib
import hmac
import tbaapiv3client


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


with open("config.json") as f:
    config: dict[str] = json.load(f)
tba_secret = config['tba_webhook_secret']


# only include qualifying matches (no semifinals, finals, etc.)
INTERESTING_LEVELS = ['qm']


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


print("startup testing server")

t = threading.Thread(target=update_thread, daemon=True)
t.start()
print("started testing update thread")


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

    print("testing server handling:")
    print(f"\t`{method=}`")
    print(f"\t`{path=}`")
    print(f"\t`{query=}`")
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
