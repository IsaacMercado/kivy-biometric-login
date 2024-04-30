import json
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

import pyseto
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from pyseto import Key, PysetoError

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "452f341a250444e0ebae9fcf2f6c639330d10d3705750f33bc9318dd31163b96"
)
ACCESS_TOKEN_EXPIRE_MINUTES = 30

paseto_key = Key.new(
    version=4,
    purpose="local",
    key=SECRET_KEY.encode(),
)


class UserStore:
    def __init__(self, filename: str):
        with open(filename, "a") as f:
            pass
        self.filename = filename
        self.users = {}
        self.load()

    def load(self):
        try:
            with open(self.filename, "r") as f:
                self.users = json.load(f)
        except FileNotFoundError:
            self.save()

    def save(self):
        with open(self.filename, "w") as f:
            json.dump(self.users, f)

    def get(self, username: str):
        return self.users.get(username)

    def create(self, username: str, user: dict):
        self.users[username] = user
        self.save()

    def update(self, username: str, user: dict):
        assert username in self.users
        assert "username" not in user

        self.users[username].update(user)
        self.save()

    def delete(self, username: str):
        del self.users[username]
        self.save()


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserCreateIn(User):
    password: str


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = UserStore(os.getenv("USERS_DB", "users.json"))

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db: UserStore, username: str):
    user_dict = db.get(username)
    if user_dict:
        return UserInDB(**user_dict)


def authenticate_user(db: UserStore, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_paseto = pyseto.encode(paseto_key, payload=to_encode)
    return encoded_paseto


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = pyseto.decode(paseto_key, token, deserializer=json).payload
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except PysetoError as error:
        raise credentials_exception from error

    user = get_user(fake_users_db, username=token_data.username)

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(
        fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return current_user


@app.post("/users/")
async def create_user(user: UserCreateIn) -> User:
    hashed_password = get_password_hash(user.password)
    user_dict = user.model_dump()
    user_dict["hashed_password"] = hashed_password
    del user_dict["password"]
    fake_users_db.create(user.username, user_dict)
    return user
