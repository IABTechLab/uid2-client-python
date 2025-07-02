import base64


class Envelope:
    def __init__(self, envelope, nonce):
        self._binary_envelope = envelope
        self._nonce = nonce

    @property
    def envelope(self):
        """
        Returns an encrypted request envelope which can be used in the POST body of a <a href="https://unifiedid.com/docs/endpoints/summary-endpoints">UID2 endpoint</a>.
        See <a href="https://unifiedid.com/docs/getting-started/gs-encryption-decryption#encrypted-request-envelope">Encrypted Request Envelope</a>
        """
        return base64.b64encode(self._binary_envelope)

    @property
    def nonce(self):
        return self._nonce

    @property
    def binary_envelope(self):
        return self._binary_envelope
