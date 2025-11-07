"""
Web Bot Auth Library

A library to check for AI Bot Authentication using the latest HTTP header Signature.
"""

__version__ = "0.3.1"

import base64
import hashlib
import json
import requests
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datetime import datetime, timedelta
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
    algorithms,
)


class SingleKeyResolver(HTTPSignatureKeyResolver):
    """
    SingleKeyResolver(key)

    A simple key resolver that always returns the same key for any key ID.
    """

    def __init__(
        self,
        key,
    ):
        self.key = key

    def resolve_public_key(self, key_id: str):
        return self.key

    def resolve_private_key(self, key_id: str):
        return self.key


class BotAuth:
    """
    BotAuth(url)

    @PARAMS
    - LocalKeys : Path where the local keys are stored.  Format: list[dict[str, str]]

    @METHODS
    - get_local_keys() -> -> list[dict[str, str]]
    - get_remote_keys() -> list[dict[str, str]]
    - get_header()-> dict[str, str]
    """

    def __init__(
        self,
        localKeys,
        signAgent=None,
    ):
        self.localKeys = localKeys
        self.signAgent = signAgent

    def get_local_keys(self) -> list[dict[str, str]]:
        """
        DUMMY MODULE: TEMPLATE FOR TESTING
        "Deprecated" - This function is a placeholder for local keys.
        It should return a list of dictionaries containing key information.
        """
        # return [
        #     {
        #         "kty": "OKP",
        #         "crv": "Ed25519",
        #         "kid": "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
        #         "d": "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
        #         "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
        #     }
        # ]
        return self.localKeys

    def get_remote_header(self, url) -> list[dict[str, str]]:
        """
        @Params:
        - url: str [URL of website]
        """
        res = requests.get(url)
        try:
            res_json = res.headers
            return res_json
        except Exception as e:
            print(e)
            return None

    def get_remote_keys(self, url) -> list[dict[str, str]]:
        """
        This function fetches the remote keys from the given URL.
        Using the /.well-known/http-message-signatures-directory endpoint.
        """
        domain = requests.utils.urlparse(url).netloc
        well_known_url = (
            f"https://{domain}/.well-known/http-message-signatures-directory"
        )
        res = requests.get(well_known_url)
        try:
            res_json = res.json()
            return res_json
        except Exception as e:
            print(e)
            return None

    def _base64url_decode(self, val):
        return base64.urlsafe_b64decode(val + "=" * (-len(val) % 4))

    def _base64_encode_bytes(self, val):
        return base64.b64encode(val).decode("ascii")

    def _base64url_nopad_encode_bytes(self, val):
        return base64.urlsafe_b64encode(val).decode("ascii").strip("=")

    def _jwt_to_private_key(self, jwk):
        return Ed25519PrivateKey.from_private_bytes(self._base64url_decode(jwk["d"]))

    def _public_key_to_jwk_thumbprint(self, public_key):
        """
        Compute the base64url JWK SHA-256 Thumbprint for an Ed25519 public key.
        """
        # JWK Thumbprint according to RFC 7638, base64url with padding and sha256

        jwk_dict = {
            "crv": "Ed25519",
            "kty": "OKP",
            "x": self._base64url_nopad_encode_bytes(public_key.public_bytes_raw()),
        }

        jwk_json = json.dumps(jwk_dict, separators=(",", ":"), sort_keys=True)
        sha256_hash = hashlib.sha256(jwk_json.encode("utf-8")).digest()
        thumbprint = self._base64url_nopad_encode_bytes(sha256_hash)

        return thumbprint

    # def _jwk_to_public_key_bytes(self, jwk):
    #     private_key = self.jwk_to_private_key(jwk)
    #     public_key = private_key.public_key()
    #     return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def get_bot_signature_header(self, url) -> dict[str, str]:
        """
        This creates and build the signature of the bot based on the key provided.
        Append the result to the request Header before making the result.
        """
        local_keys = self.localKeys

        ## Get similar key in local repo
        selected_key = local_keys[0]

        private_key = self._jwt_to_private_key(selected_key)
        resolver = SingleKeyResolver(private_key)
        signer = HTTPMessageSigner(
            signature_algorithm=algorithms.ED25519, key_resolver=resolver
        )

        created = datetime.fromtimestamp(time.time())
        expires = created + timedelta(minutes=5)

        headers = {"Signature-Agent": self.signAgent} if self.signAgent else {}
        request = requests.Request(
            "GET",
            url,
            headers={
                **headers,
            },
        )

        key_id = self._public_key_to_jwk_thumbprint(private_key.public_key())
        covered_components = (
            ("@authority", "signature-agent") if self.signAgent else ["@authority"]
        )
        signer.sign(
            request,
            key_id=key_id,
            covered_component_ids=covered_components,
            created=created,
            expires=expires,
            tag="web-bot-auth",
            label="sig1",
        )

        header = {
            "Signature-Input": request.headers["Signature-Input"],
            "Signature": request.headers["Signature"],
            **headers,
        }

        return header


# Export the main class and version
__all__ = ["BotAuth", "__version__"]
