import datetime
import json


class IdentityTokens:
    def __init__(self, advertising_token, refresh_token, refresh_response_key, identity_expires,
                 refresh_expires, refresh_from, json_string):
        self._advertising_token = advertising_token
        self._refresh_token = refresh_token
        self._refresh_response_key = refresh_response_key
        self._identity_expires = identity_expires
        self._refresh_expires = refresh_expires
        self._refresh_from = refresh_from
        self._json_string = json_string

    @staticmethod
    def from_json_string(json_string):
        assert json_string is not None, "jsonString must not be null"

        try:
            return IdentityTokens.from_json(json.loads(json_string))
        except json.JSONDecodeError:
            print("Invalid json string")
            return None
        except KeyError:
            print("Missing field in json string")
            return None

    @staticmethod
    def from_json(json_obj):
        return IdentityTokens(
            json_obj.get("advertising_token"),
            json_obj.get("refresh_token"),
            json_obj.get("refresh_response_key"),
            json_obj.get("identity_expires"),
            json_obj.get("refresh_expires"),
            json_obj.get("refresh_from"),
            json.dumps(json_obj)
        )

    def is_due_for_refresh(self):
        return self.is_due_for_refresh_impl(datetime.datetime.now())

    def get_advertising_token(self):
        return self._advertising_token

    def get_refresh_token(self):
        return self._refresh_token

    def get_json_string(self):
        return self._json_string

    def is_refreshable(self):
        return self.is_refreshable_impl(datetime.datetime.now())

    def is_refreshable_impl(self, timestamp):
        refresh_expires = self._refresh_expires
        if refresh_expires is None or timestamp.timestamp() > refresh_expires:
            return False
        return self._refresh_token is not None

    def is_due_for_refresh_impl(self, timestamp):
        return timestamp.timestamp() > self._refresh_from or self.has_identity_expired(timestamp)

    def has_identity_expired(self, timestamp):
        return timestamp.timestamp() > self._identity_expires

    def get_refresh_response_key(self):
        return self._refresh_response_key

    def get_identity_expires(self):
        return self._identity_expires

    def get_refresh_expires(self):
        return self._refresh_expires

    def get_refresh_from(self):
        return self._refresh_from
