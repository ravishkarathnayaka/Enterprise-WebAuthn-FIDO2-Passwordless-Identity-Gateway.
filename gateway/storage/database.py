"""Database models and persistence layer for Users and WebAuthn Credentials."""

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base, relationship

from gateway.config import settings

Base = declarative_base()

# SQLAlchemy Async Engine & Sessionmaker
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    display_name = Column(String(150), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(String(255), primary_key=True)  # Base64url-encoded credential ID
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    public_key = Column(LargeBinary, nullable=False)  # Raw public key bytes (COSE/PEM)
    sign_count = Column(Integer, default=0, nullable=False)
    aaguid = Column(String(64), nullable=True)
    nickname = Column(String(100), nullable=True)  # Friendly label (e.g. Work MacBook TouchID)
    transports = Column(Text, nullable=True)  # JSON-encoded transports list
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_used_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    user = relationship("User", back_populates="credentials")

    @property
    def transport_list(self) -> list[str]:
        if self.transports:
            try:
                return json.loads(self.transports)
            except Exception:
                return []
        return []


async def init_db() -> None:
    """Initialize database tables and run lightweight schema migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        def _migrate_schema(connection):
            try:
                res = connection.exec_driver_sql("PRAGMA table_info(credentials)").fetchall()
                col_names = [r[1] for r in res]
                if col_names:
                    if "nickname" not in col_names:
                        connection.exec_driver_sql("ALTER TABLE credentials ADD COLUMN nickname VARCHAR(100)")
                    if "transports" not in col_names:
                        connection.exec_driver_sql("ALTER TABLE credentials ADD COLUMN transports TEXT")
                    if "aaguid" not in col_names:
                        connection.exec_driver_sql("ALTER TABLE credentials ADD COLUMN aaguid VARCHAR(64)")
            except Exception:
                pass

        await conn.run_sync(_migrate_schema)


async def get_or_create_user(username: str, display_name: str | None = None) -> User:
    """Retrieve user by username or create a new one if not found."""
    async with AsyncSessionLocal() as session:
        query = select(User).where(User.username == username)
        result = await session.execute(query)
        user = result.scalar_one_or_none()
        if user is None:
            user = User(
                username=username,
                display_name=display_name or username,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
        return user


async def get_user_by_id(user_id: str) -> User | None:
    """Retrieve user by unique user_id."""
    async with AsyncSessionLocal() as session:
        query = select(User).where(User.id == user_id)
        result = await session.execute(query)
        return result.scalar_one_or_none()


async def get_user_by_username(username: str) -> User | None:
    """Retrieve user by username."""
    async with AsyncSessionLocal() as session:
        query = select(User).where(User.username == username)
        result = await session.execute(query)
        return result.scalar_one_or_none()


async def get_credentials_for_user(user_id: str) -> list[Credential]:
    """Retrieve all WebAuthn credentials belonging to a user."""
    async with AsyncSessionLocal() as session:
        query = select(Credential).where(Credential.user_id == user_id)
        result = await session.execute(query)
        return list(result.scalars().all())


async def get_credential_by_id(credential_id: str) -> Credential | None:
    """Retrieve a single credential by its base64url ID."""
    async with AsyncSessionLocal() as session:
        query = select(Credential).where(Credential.id == credential_id)
        result = await session.execute(query)
        return result.scalar_one_or_none()


async def save_credential(
    user_id: str,
    credential_id: str,
    public_key: bytes,
    sign_count: int = 0,
    aaguid: str | None = None,
    transports: list[str] | None = None,
) -> Credential:
    """Persist newly registered WebAuthn credential."""
    async with AsyncSessionLocal() as session:
        cred = Credential(
            id=credential_id,
            user_id=user_id,
            public_key=public_key,
            sign_count=sign_count,
            aaguid=aaguid,
            transports=json.dumps(transports) if transports else None,
            created_at=datetime.now(UTC),
            last_used_at=datetime.now(UTC),
        )
        session.add(cred)
        await session.commit()
        await session.refresh(cred)
        return cred


async def update_credential_sign_count(credential_id: str, new_sign_count: int) -> None:
    """Update stored signature counter for anti-replay enforcement."""
    async with AsyncSessionLocal() as session:
        query = select(Credential).where(Credential.id == credential_id)
        result = await session.execute(query)
        cred = result.scalar_one_or_none()
        if cred:
            cred.sign_count = new_sign_count
            cred.last_used_at = datetime.now(UTC)
            await session.commit()


async def delete_credential(credential_id: str, user_id: str) -> bool:
    """Revoke and delete a specific credential belonging to a user."""
    async with AsyncSessionLocal() as session:
        query = select(Credential).where(Credential.id == credential_id, Credential.user_id == user_id)
        result = await session.execute(query)
        cred = result.scalar_one_or_none()
        if cred:
            await session.delete(cred)
            await session.commit()
            return True
        return False


async def rename_credential(credential_id: str, user_id: str, nickname: str) -> bool:
    """Update friendly label/nickname for a user credential."""
    async with AsyncSessionLocal() as session:
        query = select(Credential).where(Credential.id == credential_id, Credential.user_id == user_id)
        result = await session.execute(query)
        cred = result.scalar_one_or_none()
        if cred:
            cred.nickname = nickname
            await session.commit()
            return True
        return False

