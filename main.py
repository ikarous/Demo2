"""
NOTE: For real apps, DO NOT store plaintext passwords. Hash & salt them, use HTTPS, and
consider session revocation, refresh tokens, etc. This is strictly for a demo.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

# ---------- Demo configuration ----------
SECRET_KEY = "demo-secret-key-change-me"  # demo only
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # short-lived token for demo

# Hard-coded demo users (plaintext passwords — demo only!)
FAKE_USERS_DB: Dict[str, Dict[str, Any]] = {
    "jane": {
        "username": "jane",
        "password": "janepword",  # plaintext for demo
        "full_name": "Jane Doe",
        "roles": ["demo", "reader"],
    },
    "john": {
        "username": "john",
        "password": "johnpword",
        "full_name": "John Doe",
        "roles": ["demo", "admin"],
    },
}

# OAuth2 scheme that expects a Bearer token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(title="FastAPI OAuth Demo: Username/Password -> Token")


# ---------- Pydantic models ----------
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class User(BaseModel):
    username: str
    full_name: str
    roles: list[str]


# ---------- Auth helpers ----------

def authenticate_user(username: str, password: str) -> Optional[User]:
    user = FAKE_USERS_DB.get(username)
    if not user:
        return None
    if password != user["password"]:
        return None
    return User(username=user["username"], full_name=user["full_name"], roles=user["roles"])  # type: ignore[arg-type]


def create_access_token(subject: str, extra_data: Optional[dict] = None, expires_delta: Optional[timedelta] = None) -> str:
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    to_encode = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    if extra_data:
        to_encode.update(extra_data)
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    payload = decode_token(token)
    username: Optional[str] = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token: missing subject")
    user_data = FAKE_USERS_DB.get(username)
    if not user_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer exists")
    return User(username=user_data["username"], full_name=user_data["full_name"], roles=user_data["roles"])  # type: ignore[arg-type]


# ---------- Routes ----------

@app.post("/token", response_model=Token, summary="Exchange username/password for a bearer token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Accepts application/x-www-form-urlencoded form with fields:
        - username
        - password

    Returns a JSON object with the bearer token to use in Authorization header.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        # Standard OAuth2 error pattern
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # You can embed arbitrary claims for demos (e.g., roles)
    token = create_access_token(subject=user.username, extra_data={"roles": user.roles})
    return Token(access_token=token, token_type="bearer", expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

@app.get("/public", summary="Unprotected route — no token required")
async def public_route():
    return {"message": "This route is public. No Authentication required"}

@app.get("/me", response_model=User, summary="Return current user (requires bearer token)")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# Example of role-protected route (simple demo check)
@app.get("/admin", summary="Example: restricted role route")
async def admin_area(current_user: User = Depends(get_current_user)):
    if "admin" not in current_user.roles:
        raise HTTPException(status_code=403, detail="Forbidden: admin role required")
    return {"message": f"Welcome, {current_user.full_name}! You have admin access."}

