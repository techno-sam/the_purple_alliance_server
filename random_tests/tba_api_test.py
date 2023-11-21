# https://github.com/TBA-API/tba-api-client-python/blob/master/docs/EventApi.md
import json
import time
import tbaapiv3client
from tbaapiv3client.rest import ApiException
from pprint import pprint

with open("../config.json") as f:
    config: dict[str] = json.load(f)
    if "tba_api_key" not in config:
        raise ValueError("Missing TBA API key in config.json")
    if config["tba_api_key"] == "<NONE>":
        raise ValueError("TBA API key is not set in config.json")
    if "event_key" not in config:
        raise ValueError("Missing event key in config.json")

configuration = tbaapiv3client.Configuration(
    host="https://www.thebluealliance.com/api/v3",
    api_key={
        'X-TBA-Auth-Key': config["tba_api_key"]
    }
)


class TeamData:
    def __init__(self, team_number: int, team_key: str):
        self.team_number = team_number
        self.team_key = team_key
        self.wins = 0
        self.ties = 0
        self.losses = 0

    def __repr__(self) -> str:
        return f"{self.team_number} w-l-t: {self.wins}-{self.losses}-{self.ties}"


with tbaapiv3client.ApiClient(configuration) as client:
    evt_key: str = config["event_key"]
    event_api = tbaapiv3client.EventApi(client)

    team_data: list[tbaapiv3client.Team] = event_api.get_event_teams(evt_key)
    teams: dict[str, TeamData] = {team.key: TeamData(team.team_number, team.key) for team in team_data}
    pprint(teams)

    match_data: list[tbaapiv3client.Match] = event_api.get_event_matches(evt_key)

    # only include qualifying matches (no semifinals, finals, etc.)
    interesting_levels = ['qm']
    for match in match_data:
        if match.comp_level in interesting_levels:
            print(f"Match {match.key} ({match.comp_level})")
            red: tbaapiv3client.MatchAlliance = match.alliances.red
            blue: tbaapiv3client.MatchAlliance = match.alliances.blue

            if red.score is None or blue.score is None or red.score == -1 or blue.score == -1:
                continue  # this match hasn't been played yet

            red_keys: list[str] = red.team_keys
            blue_keys: list[str] = blue.team_keys

            winner: str = match.winning_alliance
            if winner == "red":
                for key in red_keys:
                    if key in teams:
                        teams[key].wins += 1
                for key in blue_keys:
                    if key in teams:
                        teams[key].losses += 1
            elif winner == "blue":
                for key in red_keys:
                    if key in teams:
                        teams[key].losses += 1
                for key in blue_keys:
                    if key in teams:
                        teams[key].wins += 1
            else:
                for key in red_keys:
                    if key in teams:
                        teams[key].ties += 1
                for key in blue_keys:
                    if key in teams:
                        teams[key].ties += 1

    print("\n\nAfter scoring matches:")
    pprint(teams)
