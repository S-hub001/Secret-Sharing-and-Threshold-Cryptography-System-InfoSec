import hmac
import hashlib

SECRET_KEY = b"super_secret_key"


def generate_hmac(data: str) -> str:
    return hmac.new(SECRET_KEY, data.encode(), hashlib.sha256).hexdigest()


def verify_hmac(data: str, signature: str) -> bool:
    expected = generate_hmac(data)
    return hmac.compare_digest(expected, signature)