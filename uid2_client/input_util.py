import hashlib
import base64
from datetime import timezone


def is_phone_number_normalized(phone_number):
    min_phone_number_digits = 10
    max_phone_number_digits = 15

    if phone_number is None or len(phone_number) < min_phone_number_digits:
        return False

    if phone_number[0] != '+':
        return False

    for char in phone_number[1:]:
        if not char.isdigit():
            return False

    total_digits = sum(char.isdigit() for char in phone_number[1:])

    return min_phone_number_digits <= total_digits <= max_phone_number_digits


def normalize_email_string(email):
    pre_sb = []
    pre_sb_specialized = []
    sb = []
    ws_buffer = []

    class EmailParsingState:
        Starting = 1
        Pre = 2
        SubDomain = 3

    parsing_state = EmailParsingState.Starting

    in_extension = False

    for i in range(len(email)):
        c_given = email[i]
        if 'A' <= c_given <= 'Z':
            c = chr(ord(c_given) + 32)
        else:
            c = c_given

        if parsing_state == EmailParsingState.Starting:
            if c == ' ':
                continue
            else:
                parsing_state = EmailParsingState.Pre

        if parsing_state == EmailParsingState.Pre:
            if c == '@':
                parsing_state = EmailParsingState.SubDomain
            elif c == '.':
                pre_sb.append(c)
            elif c == '+':
                pre_sb.append(c)
                in_extension = True
            else:
                pre_sb.append(c)
                if not in_extension:
                    pre_sb_specialized.append(c)
        elif parsing_state == EmailParsingState.SubDomain:
            if c == '@':
                return None
            elif c == ' ':
                ws_buffer.append(c)
                continue
            if len(ws_buffer) > 0:
                sb.extend(ws_buffer)
                ws_buffer = []
            sb.append(c)

    if len(sb) == 0:
        return None
    domain_part = ''.join(sb)

    gmail_domain = "gmail.com"
    if gmail_domain == domain_part:
        address_part_to_use = pre_sb_specialized
    else:
        address_part_to_use = pre_sb

    if len(address_part_to_use) == 0:
        return None

    return ''.join(address_part_to_use + ['@'] + [domain_part])


def is_ascii_digit(d):
    return '0' <= d <= '9'


def base64_to_byte_array(str):
    return base64.b64decode(str)


def byte_array_to_base64(b):
    return base64.b64encode(b).decode()


def get_base64_encoded_hash(input):
    return byte_array_to_base64(get_sha256_bytes(input))


def get_sha256_bytes(input):
    return hashlib.sha256(input.encode()).digest()


def normalize_and_hash_email(email):
    normalized_email = normalize_email_string(email)
    if normalized_email is None:
        raise ValueError("invalid email address: " + email)
    return get_base64_encoded_hash(normalized_email)


def normalize_and_hash_phone(phone):
    if not is_phone_number_normalized(phone):
        raise ValueError("phone number is not normalized: " + phone)
    return get_base64_encoded_hash(phone)


def get_datetime_utc_iso_format(timestamp):
    dt_utc = timestamp.astimezone(timezone.utc)
    dt_utc_without_tz = dt_utc.replace(tzinfo=None)
    return dt_utc_without_tz.isoformat()
