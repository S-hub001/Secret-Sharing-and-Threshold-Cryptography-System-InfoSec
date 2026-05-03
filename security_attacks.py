from crypto_engine import reconstruct_secret
from utils.hmac_service import generate_hmac


# Attack 1: insufficient shares
def attack_insufficient(shares):
    return reconstruct_secret(shares[:2])


# Attack 2: tampering attack
def attack_tamper(shares):
    fake = list(shares)
    fake[0] = (fake[0][0], fake[0][1] + 999)
    return fake


# Attack 3: brute force explanation
def brute_force_explanation():
    return """
    Brute force is impossible because:
    - Polynomial degree = k-1
    - Infinite possible polynomials exist
    - Requires k points to uniquely solve
    """


# Attack 4: insider attack simulation
def insider_attack(shares):
    return reconstruct_secret(shares[:2])  # collusion of 2 insiders