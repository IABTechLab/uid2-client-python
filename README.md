# UID2 SDK for Python

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review [the governance rules](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md).

This SDK simplifies integration with UID2 for those using Python.

## Dependencies

This SDK supports Python 3.6 and above.

## Quick Start

Connect to the UID2 service, refresh the encryption keys, and then use the keys to decrypt an advertising token, to arrive at the corresponding advertising ID:

```
from uid2_client import Uid2Client, decrypt

client = Uid2Client('https://prod.uidapi.com', 'my-auth-token', 'my-secret-key')
keys = client.refresh_keys()
advertising_token = 'AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A=='
decrypted_token = decrypt(advertising_token, keys)
print(decrypted_token.uid2)
```

Additional examples are in the [examples] directory:
* [sample_auto_refresh.py](examples/sample_auto_refresh.py)
* [sample_client.py](examples/sample_client.py)
  * Includes an example to encrypt a raw UID2 into an advertising token for UID2 sharing.

## Usage for Publishers

1. Create an instance of Uid2PublisherClient
 
   `client = Uid2PublisherClient(UID2_BASE_URL, UID2_API_KEY, UID2_SECRET_KEY)`

2. Call a function that takes the user's email address or phone number as input and generates a `TokenGenerateResponse` object. The following example uses an email address:
 
   `token_generate_response = client.generate_token(TokenGenerateInput.from_email(emailAddress).do_not_generate_tokens_for_opted_out())`

   >IMPORTANT: Be sure to call this function only when you have obtained legal basis to convert the user’s [directly identifying information (DII)](https://unifiedid.com/docs/ref-info/glossary-uid#gl-dii) to UID2 tokens for targeted advertising.
   
   >`do_not_generate_tokens_for_opted_out()` applies `policy=1` in the [/token/generate](https://unifiedid.com/docs/endpoints/post-token-generate#token-generation-policy) call. Without this, `policy` is omitted to maintain backwards compatibility.

### Standard Integration

If you're using standard integration (client and server) (see [UID2 SDK for JavaScript Integration Guide](https://unifiedid.com/docs/guides/publisher-client-side)), follow this step:

* Send this identity as a JSON string back to the client (to use in the [identity field](https://unifiedid.com/docs/sdks/client-side-identity#initopts-object-void)) using the following:

    `token_generate_response.get_identity_json_string()` //Note: this method returns `None` if the user has opted out, so be sure to handle that case.

### Server-Only Integration

If you're using server-only integration (see [Publisher Integration Guide, Server-Only](https://unifiedid.com/docs/guides/custom-publisher-integration)):

1. Store this identity as a JSON string in the user's session, using the `token_generate_response.get_identity_json_string()` function. This method returns `None` if the user has opted out, so be sure to handle that case.
2. To retrieve the user's UID2 token, use:

   ```
   identity = token_generate_response.get_identity()
   if identity:
      advertising_token = identity.get_advertising_token()
   ```
4. When the user accesses another page, or on a timer, determine whether a refresh is needed:
   1. Retrieve the identity JSON string from the user's session, and then call the following function that takes the identity information as input and generates an `IdentityTokens` object:

      `identity = IdentityTokens.from_json_string(identityJsonString)`
   2. Determine if the identity can be refreshed (that is, the refresh token hasn't expired):

      ` if not identity or not identity.is_refreshable(): # we must no longer use this identity (for example, remove this identity from the user's session) `
   3. Determine if a refresh is needed:

      `if identity.is_due_for_refresh()):`
5. If needed, refresh the token and associated values:
 
   `token_refresh_response = client.refresh_token(identity)`
 
6. Store `token_refresh_response.get_identity_json_string()` in the user's session. If the user has opted out, this method returns `None`, indicating that the user's identity should be removed from the session. To confirm optout, you can use the `token_refresh_response.is_optout()` function.


## Development

First, build the Docker image with Python 3.6 and all dev dependencies. This is required for all subsequent commands. Run the following:

```
make docker
```

Run unit tests:

```
make test
```

Build a bdist wheel:

```
make wheel
```

Get access to an interactive shell within the Python 3.6 Docker image:

```
make shell
```

## Example Usage

To run all the example applications:

```
make examples BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
```

Alternatively, you can run specific examples:

```
make example_client BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
make example_auto_refresh BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
```
