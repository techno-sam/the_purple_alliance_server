import os.path
import typing


class DataValue:
    def __init__(self, init_dict: dict[str, typing.Any]):
        self.last_updated: int = -1
        self.init_dict = init_dict

    def from_json(self, data: dict):
        """Should only be used for loading from disk, updating from client should call update_from"""
        self.last_updated = data.get("timestamp", -1)

    def to_json(self, net: bool = False, username: str = "", team: typing.Optional["Team"] = None) -> dict:
        """Can be used for saving to disk and sending to client"""
        return {"timestamp": self.last_updated}

    def reset(self):
        self.last_updated = -1

    def update_from(self, data: dict, username: str):
        """Should only be used for updating data from client, loading from disk should call from_json"""
        if self.last_updated < data["timestamp"]:
            self.last_updated = data["timestamp"]
            self._update_from(data["value"], username)

    def _update_from(self, data, username: str):
        """Internal update method shielded by timestamp check.
        If you need custom behavior, override update_from instead"""
        raise NotImplementedError


class TextDataValue(DataValue):
    def __init__(self, init_dict: dict[str, typing.Any]):
        super().__init__(init_dict)
        self.value: str = ""

    def from_json(self, data: dict):
        super().from_json(data)
        print("Loading text from json: ", data)
        self.value = data["value"]

    def to_json(self, net: bool = False, username: str = "", team: typing.Optional["Team"] = None) -> dict:
        data = super().to_json(net)
        data["value"] = self.value
        return data

    def reset(self):
        super().reset()
        self.value = ""

    def _update_from(self, data: str, username: str):
        self.value = data


class DropdownDataValue(DataValue):
    def __init__(self, init_dict: dict[str, typing.Any]):
        super().__init__(init_dict)
        self.options: list[str] = init_dict["options"]
        assert type(self.options) == list
        self.value: str = init_dict.get("default", self.options[0])
        self.default = self.value
#        print("Init dict: ", init_dict)
        self.can_have_other = init_dict.get("other", False)
        self.other_value = ""
        if not (self.value in self.options or (self.value == "Other" and self.can_have_other)):
            self.value = self.options[0]

    def from_json(self, data: dict):
        super().from_json(data)
#        print("\n\n=================>>> Loading dropdown: ", data, "\n\n\n")
        self.value = data["value"]
        self.other_value = data.get("other_value", "")
        if not (self.value in self.options or (self.value == "Other" and self.can_have_other)):
            self.value = self.default

    def to_json(self, net: bool = False, username: str = "", team: typing.Optional["Team"] = None) -> dict:
        data = super().to_json(net)
        if net:
            data["value"] = {
                "value": self.value,
                "other": self.can_have_other,
                "other_value": self.other_value
            }
        else:
            data["value"] = self.value
            data["other"] = self.can_have_other
            data["other_value"] = self.other_value
        return data

    def reset(self):
        super().reset()
        self.value = self.default

    def _update_from(self, data: dict[str, str], username: str):
#        print(f"\n\nUpdating from: {data}, can have other: {self.can_have_other}\n\n")
        value = data['value']
        if value in self.options or (value == "Other" and self.can_have_other):
            self.value = value
        if self.can_have_other:
            self.other_value = data.get('other_value', self.other_value)


class StarRatingDataValue(DataValue):
    def __init__(self, init_dict: dict[str, typing.Any]):
        super().__init__(init_dict)
        self.values: dict[str, float] = {}
        self.single_value = init_dict.get("single", False)

    average = property(lambda self: sum(self.values.values()) / len(self.values) if self.values else None)

    def from_json(self, data: dict):
        super().from_json(data)
        self.values = data["values"]

    def to_json(self, net: bool = False, username: str = "", team: typing.Optional["Team"] = None) -> dict:
        data = super().to_json(net)
        if net:
            data["value"] = {
                "personal_value": self.values.get("single" if self.single_value else username, None),
                "average_value": self.average,
                "single": self.single_value
            }
        else:
            data["values"] = self.values
            data["single"] = self.single_value
        return data

    def reset(self):
        super().reset()
        self.values = {}

    def _update_from(self, data: dict[str, float], username: str):
        self.values["single" if self.single_value else username] = max(0.0, min(data['personal_value'], 5.0))


class CommentsDataValue(DataValue):
    def __init__(self, init_dict: dict[str, typing.Any]):
        super().__init__(init_dict)
        self.comments: dict[str, str] = {}

    def from_json(self, data: dict):
        super().from_json(data)
        self.comments = data["comments"]

    def to_json(self, net: bool = False, username: str = "", team: typing.Optional["Team"] = None) -> dict:
        data = super().to_json(net)
        if net:
            data["value"] = {
                "personal_comment": self.comments.get(username, ""),
                "other_comments": {name: comment for name, comment in self.comments.items() if name != username}
            }
        else:
            data["comments"] = self.comments
        return data

    def reset(self):
        super().reset()
        self.comments = {}

    def _update_from(self, data: dict[str, str], username: str):
        self.comments[username] = data['personal_comment']


class WinLossDataValue(DataValue):
    def __init__(self, init_dict: dict[str, typing.Any]):
        super().__init__(init_dict)

    def to_json(self, net: bool = False, username: str = "", team: typing.Optional["Team"] = None) -> dict:
        data = super().to_json(net)
        if net:
            print("Sending win loss data")
            print("Team: ", team)
            data["value"] = {
                "wins": 0 if team is None else team.wins,
                "losses": 0 if team is None else team.losses,
                "ties": 0 if team is None else team.ties
            }
        return data

    def reset(self):
        super().reset()

    def _update_from(self, data: str, username: str):
        pass


_clientSideOnlyTypes: list[str] = [
    "text",
    "photos"
    # synchronization is handled separately from the normal stuff, 'photos' is just for the client to display a button
]
_dataValueTypes: dict[str, type[DataValue]] = {
    "text_field": TextDataValue,
    "dropdown": DropdownDataValue,
    "star_rating": StarRatingDataValue,
    "comments": CommentsDataValue,
    "win_loss": WinLossDataValue
}


class Team:
    def __init__(self, number: int):
        self.number = number
        self.data: dict[str, DataValue] = {}
        self.wins: int = 0
        self.losses: int = 0
        self.ties: int = 0

    def __repr__(self) -> str:
        return f"Team({self.number}) [wlt: {self.wins}/{self.losses}/{self.ties}]"


class Scheme:
    def __init__(self, data: list):
        self.data = data
        self.creation_dict: dict[str, tuple[type[DataValue], dict[str, typing.Any]]] = {}
        for item in data:
            item: dict
            type_ = item["type"]
            if type_ in _clientSideOnlyTypes:
                continue
            if type_ not in _dataValueTypes:
                raise Exception(f"Unknown data type {type_}")
            initializer_dict = item.copy()
            self.creation_dict[item["key"]] = (_dataValueTypes[type_], initializer_dict)

    def create_team(self, number: int) -> Team:
        team = Team(number)
        for key, initializer in self.creation_dict.items():
            type_, init_dict = initializer
            team.data[key] = type_(init_dict)
        return team

    def update_team(self, team: Team) -> Team:
        """Call this on a team to ensure that it has the up-to-date scheme"""
        data_bkp = team.data
        team.data = {}
        for key, initializer in self.creation_dict.items():
            type_, init_dict = initializer
            if key in data_bkp and type(data_bkp[key]) == type_:
                team.data[key] = data_bkp[key]
            else:
                team.data[key] = type_(init_dict)
        return team


def _verify_hash(hsh: str):
    if len(hsh) < 3:
        raise ValueError("Hash must be at least 3 characters long")
    for char in hsh:
        if char not in "0123456789abcdef":
            raise ValueError("Invalid character in hash")


def verify_hash(hsh: str) -> bool:
    try:
        _verify_hash(hsh)
        return True
    except ValueError:
        print("Illegal hash was attempted")
        return False


class DataManager:
    def __init__(self, competition: str, scheme: Scheme):
        self.competition = competition
        self.scheme = scheme
        self.teams: dict[int, Team] = {}
        self.image_data: dict[str, dict[str, typing.Any]] = {}

    def update_all(self):
        for team in self.teams.values():
            self.scheme.update_team(team)

    def get_team(self, number: int, create: bool = True) -> Team | None:
        if number not in self.teams:
            if not create:
                return None
            self.teams[number] = self.scheme.create_team(number)
        return self.teams[number]

    def from_json(self, data: dict[str, dict[str, dict]]):
        for number, team_data in data.items():
            team = self.get_team(int(number))
            for key, value in team_data.items():
                team.data[key].from_json(value)

    def image_data_from_json(self, data: dict[str, dict[str, typing.Any]]):
        self.image_data = data
        for v in self.image_data.values():
            if "hash" in v and "uuid" not in v:
                v["uuid"] = v["hash"]
                del v["hash"]

    def image_path(self, hsh: str) -> str:
        _verify_hash(hsh)
        return os.path.join("saved_data", self.competition, "images", hsh[:2], f"{hsh}.jpg")

    def _verify_image_data(self):
        for hsh, dat in self.image_data.items():
            assert hsh == dat['hash']
            _verify_hash(hsh)
            assert os.path.exists(self.image_path(hsh))

    def to_json(self, net: bool = False, username: str = "") -> dict[str, dict[str, dict]]:
        scores: dict[int, tuple[int, int, int]] = {}
        if net:
            with open("score_summary.txt") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    number, wlt = line.split(": ")
                    wins, losses, ties = wlt.split("-")
                    scores[int(number.replace("frc", ""))] = (int(wins), int(losses), int(ties))
        data = {}
        for number, team in self.teams.items():
            if net:
                team.wins, team.losses, team.ties = scores.get(number, (0, 0, 0))
            team_data = {}
            for key, value in team.data.items():
                team_data[key] = value.to_json(net=net, username=username, team=team)
            data[str(number)] = team_data
        return data

    def image_data_to_json(self) -> dict[str, dict[str, typing.Any]]:
        return self.image_data

    def update_from_net(self, data: dict[str, dict[str, dict]], username: str):
        for number, team_data in data.items():
            team = self.get_team(int(number))
            for key, value in team_data.items():
                team.data[key].update_from(value, username)

    """def set_team_score(self, team_key: int, wins: int, losses: int, ties: int):
        print("Setting team score, key: ", team_key)
        team = self.get_team(team_key, create=False)
        if team is None:
            return
        print("Actually setting, wlt: ", wins, losses, ties)
        team.wins = wins
        team.losses = losses
        team.ties = ties"""
