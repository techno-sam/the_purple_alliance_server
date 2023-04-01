import typing


class DataValue:
    def __init__(self, init_dict: dict[str, typing.Any]):
        self.last_updated: int = -1
        self.init_dict = init_dict

    def from_json(self, data: dict):
        """Should only be used for loading from disk, updating from client should call update_from"""
        self.last_updated = data.get("timestamp", -1)

    def to_json(self, net: bool = False) -> dict:
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

    def to_json(self, net: bool = False) -> dict:
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
        if self.value not in self.options:
            self.value = self.options[0]
        self.default = self.value

    def from_json(self, data: dict):
        super().from_json(data)
        self.value = data["value"]
        if self.value not in self.options:
            self.value = self.default

    def to_json(self, net: bool = False) -> dict:
        data = super().to_json(net)
        data["value"] = self.value
        return data

    def reset(self):
        super().reset()
        self.value = self.default

    def _update_from(self, data: str, username: str):
        if data in self.options:
            self.value = data


_clientSideOnlyTypes: list[str] = [
    "text",
]
_dataValueTypes: dict[str, type[DataValue]] = {
    "text_field": TextDataValue,
    "dropdown": DropdownDataValue,
}


class Team:
    def __init__(self, number: int):
        self.number = number
        self.data: dict[str, DataValue] = {}


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


class DataManager:
    def __init__(self, competition: str, scheme: Scheme):
        self.competition = competition
        self.scheme = scheme
        self.teams: dict[int, Team] = {}

    def update_all(self):
        for team in self.teams.values():
            self.scheme.update_team(team)

    def get_team(self, number: int) -> Team:
        if number not in self.teams:
            self.teams[number] = self.scheme.create_team(number)
        return self.teams[number]

    def from_json(self, data: dict[str, dict[str, dict]]):
        for number, team_data in data.items():
            team = self.get_team(int(number))
            for key, value in team_data.items():
                team.data[key].from_json(value)

    def to_json(self, net: bool = False) -> dict[str, dict[str, dict]]:
        data = {}
        for number, team in self.teams.items():
            team_data = {}
            for key, value in team.data.items():
                team_data[key] = value.to_json(net)
            data[str(number)] = team_data
        return data

    def update_from_net(self, data: dict[str, dict[str, dict]], username: str):
        for number, team_data in data.items():
            team = self.get_team(int(number))
            for key, value in team_data.items():
                team.data[key].update_from(value, username)
