import json


class IdentityBucketsResponse:
    def __init__(self, response):
        self._buckets = []
        response_json = json.loads(response)
        self._status = response_json["status"]

        if not self.is_success():
            raise ValueError("Got unexpected identity buckets status: " + self._status)

        body = response_json["body"]

        for bucket in body:
            self._buckets.append(Bucket.from_json(bucket))

    def is_success(self):
        return self._status == "success"

    @property
    def buckets(self):
        return self._buckets

    @property
    def status(self):
        return self._status


class Bucket:
    def __init__(self, bucket_id, last_updated):
        self._bucket_id = bucket_id
        self._last_updated = last_updated

    def get_bucket_id(self):
        return self._bucket_id

    def get_last_updated(self):
        return self._last_updated

    @staticmethod
    def from_json(json_obj):
        return Bucket(
            json_obj.get("bucket_id"),
            json_obj.get("last_updated")
        )
