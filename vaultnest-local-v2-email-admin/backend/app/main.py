import hashlib
import os
import secrets as pysecrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Generator

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://vaultnest:vaultnest@db:5432/vaultnest")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_MINUTES = 60
APP_URL = os.getenv("APP_URL", "http://localhost:5173").rstrip("/")
SMTP_HOST = os.getenv("SMTP_HOST", "mailpit")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
MAIL_FROM = os.getenv("MAIL_FROM", "VaultNest <no-reply@vaultnest.local>")
VERIFY_HOURS = int(os.getenv("VERIFY_HOURS", "24"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@vaultnest.local").lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "AdminLocalPassword123!")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
ph = PasswordHasher()

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    secrets: Mapped[list["Secret"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    verification_tokens: Mapped[list["VerificationToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Secret(Base):
    __tablename__ = "secrets"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(50), default="Password")
    ciphertext: Mapped[str] = mapped_column(Text)
    iv: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    owner: Mapped[User] = relationship(back_populates="secrets")

class VerificationToken(Base):
    __tablename__ = "verification_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    user: Mapped[User] = relationship(back_populates="verification_tokens")


def migrate_and_seed() -> None:
    Base.metadata.create_all(engine)
    # Lightweight local MVP migration for databases created by the first ZIP.
    with engine.begin() as conn:
        for statement in [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE",
        ]:
            conn.execute(text(statement))
        conn.execute(text("UPDATE users SET email_verified = TRUE WHERE email_verified IS NULL"))
        conn.execute(text("UPDATE users SET is_active = TRUE WHERE is_active IS NULL"))
        conn.execute(text("UPDATE users SET is_admin = FALSE WHERE is_admin IS NULL"))

    with SessionLocal() as s:
        admin = s.scalar(select(User).where(User.email == ADMIN_EMAIL))
        if not admin:
            admin = User(
                email=ADMIN_EMAIL,
                password_hash=ph.hash(ADMIN_PASSWORD),
                email_verified=True,
                is_active=True,
                is_admin=True,
            )
            s.add(admin)
            s.commit()
        else:
            changed = False
            if not admin.is_admin:
                admin.is_admin = True; changed = True
            if not admin.email_verified:
                admin.email_verified = True; changed = True
            if not admin.is_active:
                admin.is_active = True; changed = True
            if changed:
                s.commit()

migrate_and_seed()

app = FastAPI(title="VaultNest API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def db() -> Generator[Session, None, None]:
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()

def token_for(user_id: int, is_admin: bool = False) -> str:
    return jwt.encode(
        {"sub": str(user_id), "admin": is_admin, "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_MINUTES)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

def create_verification_token(user: User, s: Session) -> str:
    raw = pysecrets.token_urlsafe(32)
    item = VerificationToken(
        user_id=user.id,
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=VERIFY_HOURS),
    )
    s.add(item)
    s.commit()
    return raw

def send_verification_email(user: User, raw_token: str) -> None:
    link = f"{APP_URL}/verify-email?token={raw_token}"
    msg = EmailMessage()
    msg["Subject"] = "Verify your VaultNest email"
    msg["From"] = MAIL_FROM
    msg["To"] = user.email
    msg.set_content(
        f"Welcome to VaultNest.\n\nVerify your email address by opening:\n{link}\n\n"
        f"This link expires in {VERIFY_HOURS} hours.\n\nIf you did not create this account, ignore this email."
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        if SMTP_USER:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)

def get_current_user(authorization: str | None = Header(default=None), db: Session = Depends(db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        uid = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired token")
    user = db.get(User, uid)
    if not user or not user.is_active:
        raise HTTPException(401, "Account is inactive or unavailable")
    return user

def get_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Admin access required")
    return user

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
class LoginIn(BaseModel):
    email: EmailStr
    password: str
class SecretIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    category: str = Field(default="Password", max_length=50)
    ciphertext: str
    iv: str
class SecretOut(BaseModel):
    id: int; title: str; category: str; ciphertext: str; iv: str; created_at: datetime; updated_at: datetime
class AdminLoginIn(BaseModel):
    email: EmailStr
    password: str
class AdminUserOut(BaseModel):
    id: int; email: str; email_verified: bool; is_active: bool; is_admin: bool; created_at: datetime

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/auth/register")
def register(data: RegisterIn, db: Session = Depends(db)):
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Email already registered")
    user = User(email=email, password_hash=ph.hash(data.password), email_verified=False, is_active=True, is_admin=False)
    db.add(user); db.commit(); db.refresh(user)
    try:
        raw = create_verification_token(user, db)
        send_verification_email(user, raw)
    except Exception:
        db.delete(user); db.commit()
        raise HTTPException(503, "Account created but verification email could not be sent. Check mail configuration and try again.")
    return {"message": "Account created. Check your email to verify your account.", "email": user.email}

@app.get("/auth/verify")
def verify_email(token: str, db: Session = Depends(db)):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    item = db.scalar(select(VerificationToken).where(VerificationToken.token_hash == token_hash))
    if not item or item.used_at or item.expires_at < datetime.now(timezone.utc):
        raise HTTPException(400, "Verification link is invalid or expired")
    item.used_at = datetime.now(timezone.utc)
    item.user.email_verified = True
    db.commit()
    return {"message": "Email verified successfully. You can now sign in."}

@app.post("/auth/resend-verification")
def resend_verification(data: LoginIn, db: Session = Depends(db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if not user:
        raise HTTPException(404, "Account not found")
    try: ph.verify(user.password_hash, data.password)
    except VerifyMismatchError: raise HTTPException(401, "Invalid email or password")
    if user.email_verified:
        return {"message": "Email is already verified."}
    raw = create_verification_token(user, db)
    send_verification_email(user, raw)
    return {"message": "Verification email sent."}

@app.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(db)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if not user:
        raise HTTPException(401, "Invalid email or password")
    try: ph.verify(user.password_hash, data.password)
    except VerifyMismatchError: raise HTTPException(401, "Invalid email or password")
    if not user.is_active:
        raise HTTPException(403, "Your account has been disabled by an administrator")
    if not user.email_verified:
        raise HTTPException(403, "Please verify your email before signing in")
    return {"token": token_for(user.id, user.is_admin), "user": {"id": user.id, "email": user.email, "is_admin": user.is_admin}}

@app.post("/auth/admin-login")
def admin_login(data: AdminLoginIn, db: Session = Depends(db)):
    user = db.scalar(select(User).where(User.email == data.email.lower(), User.is_admin == True))
    if not user:
        raise HTTPException(401, "Invalid admin credentials")
    try: ph.verify(user.password_hash, data.password)
    except VerifyMismatchError: raise HTTPException(401, "Invalid admin credentials")
    if not user.is_active:
        raise HTTPException(403, "Admin account is inactive")
    return {"token": token_for(user.id, True), "user": {"id": user.id, "email": user.email, "is_admin": True}}

@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "is_admin": user.is_admin, "email_verified": user.email_verified}

@app.get("/secrets", response_model=list[SecretOut])
def list_secrets(user: User = Depends(get_current_user), db: Session = Depends(db)):
    if user.is_admin:
        raise HTTPException(403, "Admin accounts do not have a personal vault")
    return list(db.scalars(select(Secret).where(Secret.user_id == user.id).order_by(Secret.updated_at.desc())))

@app.post("/secrets", response_model=SecretOut)
def create_secret(data: SecretIn, user: User = Depends(get_current_user), db: Session = Depends(db)):
    if user.is_admin: raise HTTPException(403, "Admin accounts do not have a personal vault")
    item = Secret(user_id=user.id, **data.model_dump()); db.add(item); db.commit(); db.refresh(item); return item

@app.put("/secrets/{secret_id}", response_model=SecretOut)
def update_secret(secret_id: int, data: SecretIn, user: User = Depends(get_current_user), db: Session = Depends(db)):
    item = db.scalar(select(Secret).where(Secret.id == secret_id, Secret.user_id == user.id))
    if not item: raise HTTPException(404, "Secret not found")
    for k, v in data.model_dump().items(): setattr(item, k, v)
    item.updated_at = datetime.now(timezone.utc); db.commit(); db.refresh(item); return item

@app.delete("/secrets/{secret_id}")
def delete_secret(secret_id: int, user: User = Depends(get_current_user), db: Session = Depends(db)):
    item = db.scalar(select(Secret).where(Secret.id == secret_id, Secret.user_id == user.id))
    if not item: raise HTTPException(404, "Secret not found")
    db.delete(item); db.commit(); return {"ok": True}

@app.get("/admin/users", response_model=list[AdminUserOut])
def admin_users(admin: User = Depends(get_admin), db: Session = Depends(db)):
    return list(db.scalars(select(User).order_by(User.created_at.desc())))

@app.patch("/admin/users/{user_id}/status")
def admin_user_status(user_id: int, active: bool, admin: User = Depends(get_admin), db: Session = Depends(db)):
    user = db.get(User, user_id)
    if not user: raise HTTPException(404, "User not found")
    if user.id == admin.id: raise HTTPException(400, "You cannot disable your own admin account")
    user.is_active = active; db.commit()
    return {"ok": True, "is_active": user.is_active}

@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: int, admin: User = Depends(get_admin), db: Session = Depends(db)):
    user = db.get(User, user_id)
    if not user: raise HTTPException(404, "User not found")
    if user.id == admin.id: raise HTTPException(400, "You cannot delete your own admin account")
    db.delete(user); db.commit()
    return {"ok": True}
