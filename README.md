# UID2 SDK for Python

The UID 2 Project is subject to Tech Lab IPR’s Policy and is managed by the IAB Tech Lab Addressability Working Group and Privacy & Rearc Commit Group. Please review [the governance rules](https://github.com/IABTechLab/uid2-core/blob/master/Software%20Development%20and%20Release%20Procedures.md).

This document includes:
* [Requirements](#requirements)
* [Install](#install)
* [Usage](#usage)
* [Development](#development)
* [Example Usage](#example-usage)

## Requirements

This SDK supports Python 3.6 and above.

## Install

The SDK can be installed using pip.
```
pip install uid2-client
```

## Usage

For documentation on usage, see the [UID2 SDK for Python Reference Guide](https://unifiedid.com/docs/sdks/uid2-sdk-ref-python).

## Example Usage

To run all the example applications:

```
make examples BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A== \
	RAW_UID=JCqmlLXpbbu/jTdpB2a1cNAVs8O72eMXPaQzC9Ic9mE= \
	DOMAIN=example.com
```

Alternatively, you can run specific examples:

```
make example_client BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
make example_auto_refresh BASE_URL=https://prod.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key \
	AD_TOKEN=AgAAAANRdREk+IWqqnQkZ2rZdK0TgSUP/owLryysSkUGZJT+Gy551L1WJMAZA/G2B1UMDQ20WAqwwTu6o9TexWyux0lg0HHIbmJjN6IYwo+42KC8ugaR+PX0y18qQ+3yzkxmJ/ee//4IGu/1Yq4AmO4ArXN6CeszPTxByTkysVqyQVNY2A==
```

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
