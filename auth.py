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

    