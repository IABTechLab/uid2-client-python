# UID2 SDK for Python

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review [the governance rules](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md).

This document includes:
* [Who Is this SDK for?](#who-is-this-sdk-for)
* [Requirements](#requirements)
* [Install](#install)
* [Usage for DSPs](#usage-for-dsps)
* [Usage for UID2 Sharers](#usage-for-uid2-sharers)
* [Development](#development)
  * [Example Usage](#example-usage)

## Who Is this SDK for?

This SDK simplifies integration with UID2 for DSPs and UID Sharers, as described in [UID2 Integration Guides](https://unifiedid.com/docs/category/integration-guides).

## Requirements

This SDK supports Python 3.6 and above.

## Install

The SDK can be installed using pip.
```
pip install uid2-client
```

## Usage for DSPs

Connect to the UID2 service, refresh the encryption keys, and then use the keys to decrypt an advertising token, to arrive at the corresponding advertising ID:
For examples of usage for DSPs, see [sample_client.py](examples/sample_client.py) and [sample_auto_refresh.py](examples/sample_auto_refresh.py)
```
from uid2_client import Uid2ClientFactory

# for UID2 (for EUID use EuidClientFactory)
client = Uid2ClientFactory.create('https://prod.uidapi.com', 'my-auth-token', 'my-secret-key')
client.refresh_keys()
advertising_token = 'AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A=='
decrypted_token = client.decrypt(advertising_token)
print(decrypted_token.uid2)
```

## Usage for Sharers

A UID2 sharer is a participant that wants to share UID2s or EUIDs with another participant. Raw UID2s must be encrypted into UID2 tokens before sending them to another participant. 
For examples of usage, see [sample_sharing.py](examples/sample_sharing.py) and [sample_auto_refresh.py](examples/sample_auto_refresh.py)

```
from uid2_client import Uid2ClientFactory

# for UID2 (for EUID use EuidClientFactory)
client = Uid2ClientFactory.create('https://prod.uidapi.com', 'my-auth-token', 'my-secret-key')
client.refresh_keys()
```
Senders:

1. Call the following:
```
encrypted = client.encrypt(raw_uid)
 ```
2. If encryption was successful, send the token `encrypted.uid2` to the receiver.

Receivers:

1. Call the following:
```
decrypted = client.decrypt(uid_token)
```
2. If decryption was successful, use the token `decrypted.uid2`.

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

### Example Usage

To run all the example applications:

```
make examples BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A== \
	RAW_UID=JCqmlLXpbbu/jTdpB2a1cNAVs8O72eMXPaQzC9Ic9mE=
```

Alternatively, you can run specific examples:

```
make example_client BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
make example_auto_refresh BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
```
