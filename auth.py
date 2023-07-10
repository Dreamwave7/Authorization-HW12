from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException

from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from starlette import status
from db import *

class Hash:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def verify_password(self, plain_password, hashed_password):
        return self.pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password:str):
        return self.pwd_context.hash(password)
    
SECRET_KEY = "secret_key"
ALGORITHM = "HS256"

auth_scheme = OAuth2PasswordBearer(tokenUrl="/login")

async def create_access_token(data:dict, expires_delta: Optional[float]= None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + timedelta(seconds=expires_delta)
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp":expire, "iat":datetime.utcnow(), "scope": "access_token"})
    encoded_jwt = jwt.encode(to_encode,SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def create_refresh_token(data:dict, expires_delta: Optional[float] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + timedelta(seconds= expires_delta)
    else:
        expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"iat": datetime.utcnow(), "exp":expire, "scope":"refresh_token"})
    encoded_refresh_token = jwt.encode(to_encode, SECRET_KEY, algorithm=[ALGORITHM])
    return encoded_refresh_token

async def get_email_form_refresh_token(refresh_token :str):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload["scope"] == "refresh_token":
            email = payload["sub"]
            return email
        else:
            raise ValueError
    except ValueError:
        print("error")




async def get_current_user(token:str = Depends(auth_scheme), db :Session = Depends(get_db)):
    exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="not valide credentials",headers={"WWW-auth":"Bearer"})

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload['scope'] == 'access_token':
            email = payload["sub"]
            if email is None:
                raise exception

    except JWTError as e:
        raise exception

    user :User = db.query(User).filter(User.email == email).first()
    if user is None:
        raise exception
    return user 
                           