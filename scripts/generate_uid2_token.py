#!/usr/bin/env python3
"""Generate a UID2 advertising token via /v2/token/generate (publisher client only).

Optional: after each successful generate, decrypt with BidstreamClient (same idea as
examples/sample_bidstream_client.py) using --decrypt-auth-key, --decrypt-secret-key,
--domain-name, and optional --decrypt-base-url (defaults to --base-url).

Install SDK from repo root: pip install -e .

Credentials — pick one:

  A) Explicit keys (one token; do not use --site-id / --site-name):

      python scripts/generate_uid2_token.py \\
          --base-url https://prod.uidapi.com \\
          --auth-key 'UID2-C-L-...' \\
          --secret-key '<base64>'

  B) Operator clients.json (array): pass at least one `--site-id` and/or `--site-name`
     (you do not need both — site ID alone is fine). Resolves GENERATOR `key` / `secret`:

      python scripts/generate_uid2_token.py \\
          --client-json ./clients.json \\
          --base-url https://prod.uidapi.com \\
          --site-id 999 --site-id 123

      python scripts/generate_uid2_token.py \\
          --clients-s3-uri s3://uid2-core-integ-store/clients/clients.json \\
          --base-url https://integ.uidapi.com \\
          --site-id 999,123

      # Optional: select by client `name` instead of (or in addition to) site_id:
      #   --site-name "Publisher A"
      
  C) Single object in JSON (one publisher): --client-json with key/secret; do not pass sites.

  Optional bidstream decrypt (per sample_bidstream_client.py), after each advertising token:

      --decrypt-auth-key ... --domain-name example.com \\
      [--decrypt-secret-key ...]   # optional if auth key exists in the same clients.json / S3 file
      [--decrypt-base-url URL]     # defaults to publisher --base-url

clients.json in core store: s3://{uid2|euid}-core-<stage>-store/clients/clients.json
(S3 needs: pip install boto3 or pip install 'uid2_client[scripts]')

Identity defaults to test@example.com unless you set --email / --phone / hash flags.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional, Tuple, Union


JsonData = Union[list, dict]


def _parse_s3_uri(uri: str) -> Tuple[str, str]:
    if not uri.startswith("s3://"):
        raise ValueError("S3 URI must start with s3://")
    rest = uri[5:]
    bucket, sep, key = rest.partition("/")
    if not sep or not bucket or not key:
        raise ValueError("Use s3://bucket/key")
    return bucket, key


def _load_json_from_s3(uri: str) -> JsonData:
    try:
        import boto3
    except ImportError:
        print("S3 requires boto3: pip install boto3", file=sys.stderr)
        sys.exit(1)
    bucket, key = _parse_s3_uri(uri)
    client = boto3.client("s3")
    try:
        obj = client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
    except client.exceptions.ClientError as e:
        print(f"S3 read failed: {e}", file=sys.stderr)
        sys.exit(1)
    return json.loads(body.decode("utf-8"))


def _load_json_from_path(path: str) -> JsonData:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _normalize_site_ids(raw: Optional[List[str]]) -> List[int]:
    if not raw:
        return []
    out: List[int] = []
    for chunk in raw:
        for part in str(chunk).split(","):
            part = part.strip()
            if part:
                out.append(int(part, 10))
    return out


def _row_is_generator(row: dict) -> bool:
    if not isinstance(row, dict) or row.get("disabled"):
        return False
    roles = row.get("roles") or []
    return "GENERATOR" in roles


def _generator_keys(row: dict) -> Optional[Tuple[str, str]]:
    auth = row.get("key")
    secret = row.get("secret")
    if auth and secret:
        return str(auth), str(secret)
    return None


def _find_generator_by_site_id(rows: list, site_id: int) -> Tuple[str, str, dict]:
    for row in rows:
        if not _row_is_generator(row):
            continue
        if row.get("site_id") != site_id:
            continue
        pair = _generator_keys(row)
        if pair:
            return pair[0], pair[1], row
    raise KeyError(f"no enabled GENERATOR client for site_id={site_id}")


def _find_generator_by_site_name(rows: list, name: str) -> Tuple[str, str, int, dict]:
    want = name.strip().lower()
    for row in rows:
        if not _row_is_generator(row):
            continue
        row_name = row.get("name")
        if row_name is None:
            continue
        if str(row_name).strip().lower() != want:
            continue
        pair = _generator_keys(row)
        if pair:
            return pair[0], pair[1], int(row["site_id"]), row
    raise KeyError(f"no enabled GENERATOR client with name={name!r}")


def _single_object_credentials(data: dict) -> Tuple[str, str, Optional[str]]:
    auth = data.get("auth_key") or data.get("key")
    secret = data.get("secret")
    if not auth or not secret:
        raise ValueError("object needs key/auth_key and secret")
    base_url = data.get("base_url")
    return str(auth), str(secret), str(base_url) if base_url else None


def _strip_cli_strings(args: argparse.Namespace) -> None:
    """Trim whitespace so pasted keys are not rejected by the operator."""
    for name in (
        "base_url",
        "auth_key",
        "secret_key",
        "client_json",
        "clients_s3_uri",
        "decrypt_base_url",
        "decrypt_auth_key",
        "decrypt_secret_key",
        "domain_name",
        "email",
        "phone",
        "hashed_email",
        "hashed_phone",
    ):
        v = getattr(args, name, None)
        if isinstance(v, str):
            setattr(args, name, v.strip())


def _build_token_input(args: argparse.Namespace):
    from uid2_client import TokenGenerateInput

    if args.phone:
        return TokenGenerateInput.from_phone(args.phone)
    if args.hashed_email:
        return TokenGenerateInput.from_hashed_email(args.hashed_email)
    if args.hashed_phone:
        return TokenGenerateInput.from_hashed_phone(args.hashed_phone)
    return TokenGenerateInput.from_email(args.email or "test@example.com")


def _run_generate(
    base_url: str, auth_key: str, secret_key: str, token_input, label: str
) -> Tuple[int, Optional[str]]:
    """Returns (exit_code, advertising_token or None)."""
    from uid2_client import Uid2PublisherClient

    print(f"\n=== {label} ===")
    client = Uid2PublisherClient(base_url, auth_key, secret_key)
    try:
        response = client.generate_token(token_input)
    except Exception as e:
        print(f"token generate failed: {e}", file=sys.stderr)
        return 1, None

    print("status:", response.status)
    if response.is_optout():
        print("optout: no tokens returned")
        return 0, None
    if not response.is_success():
        return 1, None

    tokens = response.get_identity()
    ad_token = tokens.get_advertising_token()
    print("advertising_token:", ad_token)
    print("refresh_token:", tokens.get_refresh_token())
    print("refresh_response_key:", tokens.get_refresh_response_key())
    print("refresh_from:", tokens.get_refresh_from())
    print("refresh_expires:", tokens.get_refresh_expires())
    print("identity_expires:", tokens.get_identity_expires())
    return 0, ad_token


def _bidstream_decrypt_report(
    decrypt_base_url: str,
    decrypt_auth_key: str,
    decrypt_secret_key: str,
    domain_name: str,
    ad_token: str,
    label: str,
) -> bool:
    """Try bidstream decrypt like sample_bidstream_client.py. Returns True if SUCCESS."""
    from uid2_client import BidstreamClient
    from uid2_client.decryption_status import DecryptionStatus

    print(f"\n--- bidstream decrypt ({label}) ---")
    client = BidstreamClient(decrypt_base_url, decrypt_auth_key, decrypt_secret_key)
    try:
        refresh_response = client.refresh()
    except Exception as e:
        print(f"decrypt: FAILED (key refresh error: {e})", file=sys.stderr)
        return False
    if not refresh_response.success:
        print(f"decrypt: FAILED (key refresh: {refresh_response.reason})", file=sys.stderr)
        reason = str(refresh_response.reason or "")
        if "ClientSecret" in reason or "encryption key" in reason.lower():
            print(
                "  hint: omit --decrypt-secret-key when using --clients-s3-uri / --client-json "
                "so the secret is taken from the file (avoids typos like Arts vs ARts). "
                "Otherwise the auth/secret pair must match sample_bidstream_client.py exactly.",
                file=sys.stderr,
            )
        return False

    try:
        result = client.decrypt_token_into_raw_uid(ad_token, domain_name)
    except Exception as e:
        print(f"decrypt: FAILED (exception: {e})", file=sys.stderr)
        return False

    ok = result.status == DecryptionStatus.SUCCESS
    if ok:
        print("decrypt: SUCCESS")
        print("  status:", result.status.value)
        print("  uid:", result.uid)
        print("  established:", result.established)
        print("  site_id:", result.site_id)
        print("  identity_type:", result.identity_type)
        print("  advertising_token_version:", result.advertising_token_version)
    else:
        print(f"decrypt: FAILED (status: {result.status.value})", file=sys.stderr)
    return ok


def _decrypt_options_enabled(args: argparse.Namespace) -> bool:
    return bool(
        args.decrypt_auth_key or args.decrypt_secret_key or args.domain_name
    )


def _validate_decrypt_options(args: argparse.Namespace) -> None:
    if not _decrypt_options_enabled(args):
        return
    missing = []
    if not args.decrypt_auth_key:
        missing.append("--decrypt-auth-key")
    if not args.domain_name:
        missing.append("--domain-name")
    if missing:
        print(
            "Bidstream decrypt requires --decrypt-auth-key and --domain-name "
            f"(missing: {', '.join(missing)}). "
            "--decrypt-secret-key is optional if that auth key exists in clients.json.",
            file=sys.stderr,
        )
        sys.exit(1)


def _lookup_secret_by_auth_key(clients_data: JsonData, auth_key: str) -> Optional[str]:
    """Return base64 secret for the row whose `key` equals auth_key."""
    if isinstance(clients_data, list):
        for row in clients_data:
            if not isinstance(row, dict):
                continue
            if row.get("key") == auth_key:
                s = row.get("secret")
                return str(s).strip() if s else None
    elif isinstance(clients_data, dict):
        row_key = clients_data.get("key") or clients_data.get("auth_key")
        if row_key == auth_key:
            s = clients_data.get("secret")
            return str(s).strip() if s else None
    return None


def _resolve_decrypt_secret_from_clients(
    args: argparse.Namespace,
    clients_data: Optional[JsonData],
    source_label: str,
) -> None:
    """Set args.decrypt_secret_key from clients.json when possible (avoids base64 typos)."""
    if not _decrypt_options_enabled(args):
        return
    auth = args.decrypt_auth_key
    if clients_data is None:
        if not args.decrypt_secret_key:
            print(
                "Bidstream with explicit --auth-key/--secret-key publish credentials "
                "requires --decrypt-secret-key (no clients.json loaded).",
                file=sys.stderr,
            )
            sys.exit(1)
        return

    from_file = _lookup_secret_by_auth_key(clients_data, auth)
    if from_file:
        if args.decrypt_secret_key and args.decrypt_secret_key != from_file:
            print(
                f"note: replacing --decrypt-secret-key with secret from {source_label} "
                f"(matched --decrypt-auth-key).",
                file=sys.stderr,
            )
        args.decrypt_secret_key = from_file
        return

    if not args.decrypt_secret_key:
        print(
            f"Bidstream: --decrypt-auth-key not found in {source_label}; "
            "pass --decrypt-secret-key manually.",
            file=sys.stderr,
        )
        sys.exit(1)


def _maybe_bidstream_decrypt(
    args: argparse.Namespace,
    publisher_base_url: str,
    ad_token: Optional[str],
    label: str,
) -> Optional[bool]:
    """None if decrypt skipped; True/False if attempted."""
    if not ad_token or not _decrypt_options_enabled(args):
        return None
    decrypt_url = args.decrypt_base_url or publisher_base_url
    return _bidstream_decrypt_report(
        decrypt_url,
        args.decrypt_auth_key,
        args.decrypt_secret_key,
        args.domain_name,
        ad_token,
        label,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate UID2 token(s) from publisher credentials or operator clients.json."
    )
    parser.add_argument("--base-url", help="Operator base URL (required unless set in client JSON object)")
    parser.add_argument("--auth-key", help="Publisher auth key (exclusive with clients file + site selection)")
    parser.add_argument("--secret-key", help="Publisher secret key, base64 (with --auth-key)")
    src = parser.add_mutually_exclusive_group()
    src.add_argument(
        "--client-json",
        help="Path to clients.json (operator array or single object)",
    )
    src.add_argument(
        "--clients-s3-uri",
        help="S3 URI, e.g. s3://uid2-core-integ-store/clients/clients.json",
    )
    parser.add_argument(
        "--site-id",
        dest="site_ids",
        action="extend",
        nargs="+",
        type=str,
        default=None,
        metavar="ID",
        help="site_id(s) with GENERATOR: --site-id 1012 1013 or --site-id 1012,1013 or repeat flag",
    )
    parser.add_argument(
        "--site-name",
        dest="site_names",
        action="append",
        default=None,
        metavar="NAME",
        help="Optional: match client `name` instead of site_id; repeat for multiple",
    )
    identity = parser.add_mutually_exclusive_group(required=False)
    identity.add_argument(
        "--email",
        help="Email (default: test@example.com if no other identity is set)",
    )
    identity.add_argument("--phone", help="E.164 phone (normalized per UID2 rules)")
    identity.add_argument("--hashed-email", dest="hashed_email", help="Pre-hashed email (base64)")
    identity.add_argument("--hashed-phone", dest="hashed_phone", help="Pre-hashed phone (base64)")
    parser.add_argument(
        "--decrypt-base-url",
        help="Bidstream key refresh URL (default: same as --base-url)",
    )
    parser.add_argument(
        "--decrypt-auth-key",
        help="Bidstream auth key (same role as sample_bidstream_client.py)",
    )
    parser.add_argument(
        "--decrypt-secret-key",
        help="Bidstream secret (base64); optional if --decrypt-auth-key exists in clients.json/S3",
    )
    parser.add_argument(
        "--domain-name",
        help="Domain for decrypt_token_into_raw_uid (sample_bidstream_client.py)",
    )
    args = parser.parse_args()
    _strip_cli_strings(args)

    _validate_decrypt_options(args)

    site_ids = _normalize_site_ids(args.site_ids)
    site_names: List[str] = list(args.site_names) if args.site_names else []

    uses_explicit_keys = bool(args.auth_key or args.secret_key)
    if uses_explicit_keys:
        if not args.auth_key or not args.secret_key:
            print("Both --auth-key and --secret-key are required together.", file=sys.stderr)
            sys.exit(1)
        if args.client_json or args.clients_s3_uri:
            print("Do not mix --auth-key/--secret-key with --client-json/--clients-s3-uri.", file=sys.stderr)
            sys.exit(1)
        if site_ids or site_names:
            print("Do not pass --site-id/--site-name with explicit --auth-key; use clients.json instead.", file=sys.stderr)
            sys.exit(1)

    if args.client_json and args.clients_s3_uri:
        print("Use only one of --client-json or --clients-s3-uri.", file=sys.stderr)
        sys.exit(1)

    token_input = _build_token_input(args)
    exit_code = 0

    if uses_explicit_keys:
        base_url = args.base_url
        if not base_url:
            print("--base-url is required with explicit keys.", file=sys.stderr)
            sys.exit(1)
        _resolve_decrypt_secret_from_clients(args, None, "")
        rc, ad_token = _run_generate(
            base_url, args.auth_key, args.secret_key, token_input, "publisher"
        )
        drc = _maybe_bidstream_decrypt(args, base_url, ad_token, "publisher")
        if drc is False:
            rc = max(rc, 2)
        sys.exit(rc)

    if not args.client_json and not args.clients_s3_uri:
        print("Provide --auth-key and --secret-key, or --client-json / --clients-s3-uri.", file=sys.stderr)
        sys.exit(1)

    if args.clients_s3_uri:
        data = _load_json_from_s3(args.clients_s3_uri)
        source_label = args.clients_s3_uri
    else:
        data = _load_json_from_path(args.client_json)
        source_label = args.client_json

    if isinstance(data, dict):
        if site_ids or site_names:
            print(
                "Single-object clients JSON does not support --site-id/--site-name; omit site flags.",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            auth_key, secret_key, base_from_file = _single_object_credentials(data)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        base_url = args.base_url or base_from_file
        if not base_url:
            print("Set --base-url or include base_url in client JSON object.", file=sys.stderr)
            sys.exit(1)
        _resolve_decrypt_secret_from_clients(args, data, source_label)
        rc, ad_token = _run_generate(base_url, auth_key, secret_key, token_input, "publisher")
        drc = _maybe_bidstream_decrypt(args, base_url, ad_token, "publisher")
        if drc is False:
            rc = max(rc, 2)
        sys.exit(rc)

    if not isinstance(data, list):
        print(f"Unsupported JSON in {source_label}.", file=sys.stderr)
        sys.exit(1)

    if not site_ids and not site_names:
        print(
            "Operator clients array requires at least one --site-id and/or --site-name.",
            file=sys.stderr,
        )
        sys.exit(1)

    base_url = args.base_url
    if not base_url:
        print("--base-url is required when using operator clients.json array.", file=sys.stderr)
        sys.exit(1)

    _resolve_decrypt_secret_from_clients(args, data, source_label)

    seen: set = set()
    jobs: List[Tuple[str, Any]] = []
    for sid in site_ids:
        key = ("id", sid)
        if key in seen:
            continue
        seen.add(key)
        jobs.append(("id", sid))
    for name in site_names:
        key = ("name", name)
        if key in seen:
            continue
        seen.add(key)
        jobs.append(("name", name))

    for kind, val in jobs:
        try:
            if kind == "id":
                auth_key, secret_key, row = _find_generator_by_site_id(data, val)
                label = f"site_id={val} name={row.get('name')!r}"
            else:
                auth_key, secret_key, sid, row = _find_generator_by_site_name(data, val)
                label = f"site_name={val!r} site_id={sid}"
        except KeyError as e:
            print(f"{source_label}: {e}", file=sys.stderr)
            exit_code = 1
            continue

        rc, ad_token = _run_generate(base_url, auth_key, secret_key, token_input, label)
        if rc != 0:
            exit_code = rc
        else:
            drc = _maybe_bidstream_decrypt(args, base_url, ad_token, label)
            if drc is False:
                exit_code = max(exit_code, 2)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
