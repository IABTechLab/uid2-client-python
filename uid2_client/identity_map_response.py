import json


class IdentityMapResponse:
    def __init__(self, response, identity_map_input):
        self._mapped_identities = {}
        self._unmapped_identities = {}
        response_json = json.loads(response)
        self._status = response_json["status"]

        if not self.is_success():
            raise ValueError("Got unexpected identity map status: " + self._status)

        body = response_json["body"]

        for identity in body.get("mapped", []):
            raw_diis = self._get_raw_diis(identity, identity_map_input)
            mapped_identity = MappedIdentity.from_json(identity)
            for raw_dii in raw_diis:
                self._mapped_identities[raw_dii] = mapped_identity

        for identity in body.get("unmapped", []):
            raw_diis = self._get_raw_diis(identity, identity_map_input)
            unmapped_identity = UnmappedIdentity.from_json(identity)
            for raw_dii in raw_diis:
                self._unmapped_identities[raw_dii] = unmapped_identity

    @staticmethod
    def _get_raw_diis(identity, identity_map_input):
        identifier = identity["identifier"]
        return identity_map_input.get_raw_diis(identifier)

    def is_success(self):
        return self._status == "success"

    @property
    def mapped_identities(self):
        return self._mapped_identities

    @property
    def unmapped_identities(self):
        return self._unmapped_identities

    @property
    def status(self):
        return self._status


class MappedIdentity:
    def __init__(self, raw_uid, bucket_id):
        self._raw_uid = raw_uid
        self._bucket_id = bucket_id

    def get_raw_uid(self):
        return self._raw_uid

    def get_bucket_id(self):
        return self._bucket_id

    @staticmethod
    def from_json(json_obj):
        return MappedIdentity(
            json_obj.get("advertising_id"),
            json_obj.get("bucket_id")
        )


class UnmappedIdentity:
    def __init__(self, reason):
        self.reason = reason

    def get_reason(self):
        return self.reason

    @staticmethod
    def from_json(json_obj):
        return UnmappedIdentity(
            json_obj.get("reason")
        )
