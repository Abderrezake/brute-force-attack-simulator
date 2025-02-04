from passlib.hash import pbkdf2_sha256
import bcrypt
import hashlib

# Méthodes modernes (sécurisées)
def hash_bcrypt(password: str) -> bytes:
    """Hachage avec bcrypt (sécurisé, lent)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_bcrypt(password: str, hashed_password: bytes) -> bool:
    """Vérification bcrypt."""
    return bcrypt.checkpw(password.encode(), hashed_password)

def hash_pbkdf2(password: str) -> str:
    """Hachage avec PBKDF2-SHA256 (via Passlib)."""
    return pbkdf2_sha256.hash(password)

def verify_pbkdf2(password: str, hashed_password: str) -> bool:
    """Vérification PBKDF2-SHA256."""
    return pbkdf2_sha256.verify(password, hashed_password)

# Méthodes faibles (pour démonstration)
def hash_sha256(password: str) -> str:
    """Hachage SHA-256 (non sécurisé pour les mots de passe)."""
    return hashlib.sha256(password.encode()).hexdigest()

def hash_md5(password: str) -> str:
    """Hachage MD5 (déprécié)."""
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha3(password: str) -> str:
    """Hachage SHA3-256."""
    return hashlib.sha3_256(password.encode()).hexdigest()