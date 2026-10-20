"""secure_app_module.py

Unified secure module combining:
1. User Authentication (JWT + Password Hashing) — PyJWT only (no python-jose)
2. Redis Cache Connection
3. SQLAlchemy Media Model for file storage

Security note (2026-10-20):
  python-jose was removed due to algorithm-confusion with DER-encoded keys.
  All decode paths MUST pass an explicit algorithms allowlist.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
import redis
import jwt
from jwt.exceptions import PyJWTError
from passlib.context import CryptContext
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean, BigInteger
)
from sqlalchemy.sql import func
from app.config import settings
from app.core.database import Base

pwd_context: CryptContext = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALLOWED_JWT_ALGORITHMS: List[str] = [
    a.strip()
    for a in str(getattr(settings, "algorithm", "HS256") or "HS256").split(",")
    if a.strip() and a.strip().lower() not in ("none", "")
]
if not ALLOWED_JWT_ALGORITHMS:
    ALLOWED_JWT_ALGORITHMS = ["HS256"]


def create_access_token(data: Dict[str, str], expires_delta: Optional[timedelta] = None) -> str:
    to_encode: Dict = data.copy()
    expire: datetime = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode.update({"exp": expire})
    alg = ALLOWED_JWT_ALGORITHMS[0]
    return jwt.encode(to_encode, settings.secret_key, algorithm=alg)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_token(token: str) -> Optional[str]:
    """Decode JWT with explicit algorithms allowlist — rejects alg confusion."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=ALLOWED_JWT_ALGORITHMS,
            options={
                "require": ["exp"],
                "verify_signature": True,
                "verify_exp": True,
            },
        )
        return payload.get("sub")
    except PyJWTError:
        return None


redis_client: redis.Redis = redis.from_url(settings.redis_url, decode_responses=True)


def get_redis() -> redis.Redis:
    return redis_client


class Media(Base):
    __tablename__ = "media"

    id: int = Column(Integer, primary_key=True, index=True)
    filename: str = Column(String, nullable=False)
    original_filename: Optional[str] = Column(String, nullable=True)
    file_path: str = Column(String, nullable=False)
    file_url: Optional[str] = Column(String, nullable=True)
    file_type: str = Column(String, nullable=False)
    mime_type: str = Column(String, nullable=False)
    file_size: int = Column(BigInteger, nullable=False)
    width: Optional[int] = Column(Integer, nullable=True)
    height: Optional[int] = Column(Integer, nullable=True)
    duration: Optional[int] = Column(Integer, nullable=True)
    is_processed: bool = Column(Boolean, default=False)
    processing_status: str = Column(String, default="pending")
    title: Optional[str] = Column(String, nullable=True)
    description: Optional[str] = Column(Text, nullable=True)
    alt_text: Optional[str] = Column(String, nullable=True)
    storage_provider: str = Column(String, default="local")
    storage_bucket: Optional[str] = Column(String, nullable=True)
    storage_key: Optional[str] = Column(String, nullable=True)
    created_at: datetime = Column(DateTime, default=func.now())
    updated_at: datetime = Column(DateTime, default=func.now(), onupdate=func.now())
    project_id: Optional[int] = Column(Integer, ForeignKey("projects.id"), nullable=True)
    generation_id: Optional[int] = Column(Integer, ForeignKey("generations.id"), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<Media id={self.id} filename={self.filename!r} "
            f"file_type={self.file_type!r} size={self.file_size}B "
            f"status={self.processing_status!r}>"
        )
