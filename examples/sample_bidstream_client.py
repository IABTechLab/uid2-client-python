import sys
import os
import pandas as pd

from uid2_client import BidstreamClient
from uid2_client.decryption_status import DecryptionStatus
from uid2_client.encryption import EncryptionError


# this sample client decrypts an advertising token into a raw UID2
# to demonstrate decryption for DSPs
# Can process a single token or read UID2s from an Excel file

def _usage():
    print('Usage: python3 sample_bidstream_client.py <base_url> <auth_key> <secret_key> <domain_name> <ad_token_or_excel_file>', file=sys.stderr)
    print('  If the 5th argument is an .xlsx file, it will read UID2s from the "UID" column in the "GAM" sheet', file=sys.stderr)
    sys.exit(1)


def get_error_summary(exception):
    """Extract a concise root cause message from an exception."""
    # For EncryptionError with "invalid payload", show the underlying exception
    if isinstance(exception, EncryptionError):
        error_msg = str(exception)
        # If it's an "invalid payload" error, always show the underlying cause
        if error_msg == 'invalid payload' and exception.__cause__:
            root_cause = str(exception.__cause__)
            # Extract the first line and clean it up
            root_line = root_cause.split('\n')[0].strip()
            # Remove common exception prefixes if present
            if root_line.startswith(exception.__cause__.__class__.__name__ + ':'):
                root_line = root_line.split(':', 1)[1].strip()
            # Combine with "invalid payload" context
            return f"invalid payload: {root_line}"
        # For other EncryptionError messages, use as-is
        return error_msg.split('\n')[0].strip()
    
    # For other exceptions, check for chained exceptions (root cause)
    if exception.__cause__:
        root_cause = str(exception.__cause__)
        # Extract the first line and clean it up
        root_line = root_cause.split('\n')[0].strip()
        # Remove common exception prefixes if present
        if root_line.startswith(exception.__cause__.__class__.__name__ + ':'):
            root_line = root_line.split(':', 1)[1].strip()
        return root_line
    
    # Otherwise, extract the exception message
    error_msg = str(exception)
    # Remove exception class name prefix if present (e.g., "ValueError: message")
    if ':' in error_msg and error_msg.split(':')[0].strip() == exception.__class__.__name__:
        error_msg = error_msg.split(':', 1)[1].strip()
    
    return error_msg.split('\n')[0].strip()


def decrypt_token(client, ad_token, domain_name, index=None):
    """Decrypt a single token and return the result with error handling."""
    token_suffix = ad_token[-6:] if len(ad_token) >= 6 else ad_token
    try:
        decrypt_result = client.decrypt_token_into_raw_uid(ad_token, domain_name)
        
        result = {
            'index': index,
            'token': ad_token[:50] + '...' if len(ad_token) > 50 else ad_token,
            'token_suffix': token_suffix,
            'status': decrypt_result.status,
            'uid': decrypt_result.uid,
            'established': decrypt_result.established,
            'site_id': decrypt_result.site_id,
            'identity_type': decrypt_result.identity_type,
            'advertising_token_version': decrypt_result.advertising_token_version,
            'is_client_side_generated': decrypt_result.is_client_side_generated,
            'error': None,
        }
        return result
    except EncryptionError as e:
        # Handle encryption errors - extract root cause
        return {
            'index': index,
            'token': ad_token[:50] + '...' if len(ad_token) > 50 else ad_token,
            'token_suffix': token_suffix,
            'status': None,
            'uid': None,
            'established': None,
            'site_id': None,
            'identity_type': None,
            'advertising_token_version': None,
            'is_client_side_generated': None,
            'error': get_error_summary(e),
        }
    except Exception as e:
        # Handle any other unexpected errors - extract root cause
        return {
            'index': index,
            'token': ad_token[:50] + '...' if len(ad_token) > 50 else ad_token,
            'token_suffix': token_suffix,
            'status': None,
            'uid': None,
            'established': None,
            'site_id': None,
            'identity_type': None,
            'advertising_token_version': None,
            'is_client_side_generated': None,
            'error': get_error_summary(e),
        }


def print_result(result):
    """Print decryption result in a formatted way."""
    token_suffix = result.get('token_suffix', '')
    if result['index'] is not None:
        print(f"\n{'='*60}")
        if token_suffix:
            print(f"Token #{result['index'] + 1} (last 6 chars: {token_suffix}): {result['token']}")
        else:
            print(f"Token #{result['index'] + 1}: {result['token']}")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        if token_suffix:
            print(f"Token (last 6 chars: {token_suffix}): {result['token']}")
        else:
            print(f"Token: {result['token']}")
        print(f"{'='*60}")
    
    # Check if there was an error or if status indicates failure
    if result['error'] is not None:
        print(f"ERROR: {result['error']}")
    elif result['status'] is None:
        print(f"ERROR: Unknown error occurred")
    elif result['status'] != DecryptionStatus.SUCCESS:
        print(f"ERROR: {result['status'].value}")
    else:
        print(f"Status = {result['status'].name} ({result['status'].value})")
        print(f"UID = {result['uid']}")
        print(f"Established = {result['established']}")
        print(f"Site ID = {result['site_id']}")
        print(f"Identity Type = {result['identity_type']}")
        print(f"Advertising Token Version = {result['advertising_token_version']}")
        print(f"Is Client Side Generated = {result['is_client_side_generated']}")


if len(sys.argv) < 6:
    _usage()

base_url = sys.argv[1]
auth_key = sys.argv[2]
secret_key = sys.argv[3]
domain_name = sys.argv[4]
input_arg = sys.argv[5]

# Initialize client
client = BidstreamClient(base_url, auth_key, secret_key)
refresh_response = client.refresh()
if not refresh_response.success:
    print('Failed to refresh keys due to =', refresh_response.reason, file=sys.stderr)
    sys.exit(1)

# Check if input is an Excel file
if input_arg.endswith('.xlsx') and os.path.exists(input_arg):
    # Read UID2s from Excel file
    print(f"Reading UID2s from Excel file: {input_arg}", file=sys.stderr)
    try:
        # Check if this is the specific file "Sample LR envelopes 20251113_updt.xlsx"
        excel_filename = os.path.basename(input_arg)
        is_specific_file = excel_filename == "Sample LR envelopes 20251113_updt.xlsx"
        
        if is_specific_file:
            # Read from the first sheet (default) and get column C (index 2)
            df = pd.read_excel(input_arg, sheet_name=0)
            print(f"Reading from column C of {excel_filename}", file=sys.stderr)
            
            # Get column C (3rd column, index 2)
            if df.shape[1] < 3:
                print(f"Error: File does not have column C. Available columns: {df.shape[1]}", file=sys.stderr)
                sys.exit(1)
            
            # Get column C by index (iloc[:, 2])
            column_c = df.iloc[:, 2]
            
            # Filter out invalid entries (like "Bad Envelope", NaN, empty strings)
            uid2_tokens = column_c.dropna().astype(str)
            uid2_tokens = uid2_tokens[uid2_tokens != 'Bad Envelope']
            uid2_tokens = uid2_tokens[uid2_tokens.str.strip() != ''].tolist()
        else:
            # Original behavior: Read from 'GAM' sheet, 'UID' column
            df = pd.read_excel(input_arg, sheet_name='GAM')
            
            # Get the UID2 column (it's called 'UID' in the file)
            if 'UID' not in df.columns:
                print(f"Error: 'UID' column not found in GAM sheet. Available columns: {df.columns.tolist()}", file=sys.stderr)
                sys.exit(1)
            
            # Filter out invalid entries (like "Bad Envelope")
            uid2_tokens = df['UID'].dropna().astype(str)
            uid2_tokens = uid2_tokens[uid2_tokens != 'Bad Envelope']
            uid2_tokens = uid2_tokens[uid2_tokens.str.strip() != ''].tolist()
        
        print(f"Found {len(uid2_tokens)} valid UID2 tokens to decrypt", file=sys.stderr)
        
        # Decrypt each token sequentially
        results = []
        for idx, token in enumerate(uid2_tokens):
            # Print the first 10 characters of the token from column C
            token_prefix = token[:10] if len(token) >= 10 else token
            token_suffix = token[-6:] if len(token) >= 6 else token
            
            if is_specific_file:
                print(f"\nDecrypting token {idx + 1}/{len(uid2_tokens)} (first 10 chars: {token_prefix})...", file=sys.stderr)
            else:
                print(f"\nProcessing token {idx + 1}/{len(uid2_tokens)} (last 6 chars: {token_suffix})...", file=sys.stderr)
            
            try:
                result = decrypt_token(client, token, domain_name, index=idx)
                results.append(result)
                
                # Print one-line error summary if failed, otherwise full result
                if result['error'] is not None:
                    if is_specific_file:
                        print(f"Token #{idx + 1} ({token_prefix}) FAILED: {result['error']}")
                    else:
                        print(f"Token #{idx + 1} ({token_suffix}) FAILED: {result['error']}")
                elif result['status'] is not None and result['status'] != DecryptionStatus.SUCCESS:
                    if is_specific_file:
                        print(f"Token #{idx + 1} ({token_prefix}) FAILED: {result['status'].value}")
                    else:
                        print(f"Token #{idx + 1} ({token_suffix}) FAILED: {result['status'].value}")
                else:
                    print_result(result)
            except Exception as e:
                # Catch any unexpected errors during processing
                token_suffix = token[-6:] if len(token) >= 6 else token
                token_prefix = token[:10] if len(token) >= 10 else token
                error_summary = get_error_summary(e)
                error_result = {
                    'index': idx,
                    'token': token[:50] + '...' if len(token) > 50 else token,
                    'token_suffix': token_suffix,
                    'status': None,
                    'uid': None,
                    'established': None,
                    'site_id': None,
                    'identity_type': None,
                    'advertising_token_version': None,
                    'is_client_side_generated': None,
                    'error': error_summary,
                }
                results.append(error_result)
                if is_specific_file:
                    print(f"Token #{idx + 1} ({token_prefix}) FAILED: {error_summary}")
                else:
                    print(f"Token #{idx + 1} ({token_suffix}) FAILED: {error_summary}")
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}")
        print(f"Total tokens processed: {len(results)}")
        successful = sum(1 for r in results if r.get('status') == DecryptionStatus.SUCCESS)
        print(f"Successful decryptions: {successful}")
        print(f"Failed decryptions: {len(results) - successful}")
        
    except Exception as e:
        print(f"Error reading Excel file: {e}", file=sys.stderr)
        sys.exit(1)
else:
    # Process single token
    try:
        result = decrypt_token(client, input_arg, domain_name, index=None)
        print_result(result)
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)
