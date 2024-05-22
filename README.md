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


You can run specific examples:

```
python examples/sample_bidstream_client.py BASE_URL=https://operator-integ.uidapi.com AUTH_KEY=my-auth-key SECRET_KEY=my-secret-key
	DOMAIN_NAME=domain-name AD_TOKEN=ad-token
```

## Development

First, build the Docker image with Python 3.6 and all dev dependencies. This is required for all subsequent commands. Run the following:

```
make docker
```

Build a bdist wheel:

```
make wheel
```

Get access to an interactive shell within the Python 3.6 Docker image:

```
make shell
```
Run unit tests: Use PyCharm to run the test cases