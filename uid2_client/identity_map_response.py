import json


class IdentityMapResponse:
    def __init__(self, response, identity_map_input):
        self.mapped_identities = {}
        self.unmapped_identities = {}
        response_json = json.loads(response)
        self.status = response_json["status"]

        if not self.is_success():
            raise ValueError("Got unexpected identity map status: " + self.status)

        body = self._get_body_as_json(response_json)

        for identity in body.get("mapped", []):
            raw_diis = self._get_raw_diis(identity, identity_map_input)
            mapped_identity = MappedIdentity.from_json(identity)
            for raw_dii in raw_diis:
                self.mapped_identities[raw_dii] = mapped_identity

        for identity in body.get("unmapped", []):
            raw_diis = self._get_raw_diis(identity, identity_map_input)
            unmapped_identity = UnmappedIdentity.from_json(identity)
            for raw_dii in raw_diis:
                self.unmapped_identities[raw_dii] = unmapped_identity

    @staticmethod
    def _get_body_as_json(json_response):
        return json_response["body"]

    @staticmethod
    def _get_raw_diis(identity, identity_map_input):
        identifier = identity["identifier"]
        return identity_map_input.get_raw_diis(identifier)

    def is_success(self):
        return self.status == "success"


class MappedIdentity:
    def __init__(self, raw_uid, bucket_id):
        self.raw_uid = raw_uid
        self.bucket_id = bucket_id

    def get_raw_id(self):
        return self.raw_uid

    def get_bucket_id(self):
        return self.bucket_id

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
