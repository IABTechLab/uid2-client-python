class RefreshResponse:
    def __init__(self, success, reason, keys):
        self.success = success
        self.reason = reason
        self.keys = keys

    @staticmethod
    def make_success(keys):
        return RefreshResponse(True, None, keys)

    @staticmethod
    def make_error(reason):
        return RefreshResponse(False, reason, None)
