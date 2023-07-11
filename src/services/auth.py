from typing import Optional

from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from src.database.db import *
from src.repository import users as rep_users


class Auth:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated = "auto")
    SECRETKEY = "PYTHON"
    ALGORITHM = "HS256"
    aut_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

    def verify_pass(self, ordinary_pass, hashed_pass):
        return self.pwd_context.verify(ordinary_pass, hashed_pass)
    
    def get_hash(self, password):
        return self.pwd_context.hash(password)
    
    async def create_access_token(self, data:dict, expires: Optional[float] = None):
        to_encode = data.copy()
        if expires:
             expire = datetime.utcnow() + timedelta(seconds=expires)
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"iat": datetime.utcnow(),"exp":expire, "scope":"access_token"})
        encoded_token = jwt.encode(to_encode, self.SECRETKEY, algorithm=[self.ALGORITHM])
        return encoded_token
    
    async def create_refresh_token(self, data:dict, expires:Optional[float]=None):
        to_encode = data.copy()
        if expires:
            expire = datetime.utcnow() + timedelta(seconds=expires)
        else:
            expire = datetime.utcnow() + timedelta(days=7)
        to_encode.update({"iat":datetime.utcnow(),"exp":expire,"scope":"refresh_token"})
        encoded_token = jwt.encode(to_encode, self.SECRETKEY, algorithm=[self.ALGORITHM])
        return encoded_token
    
    async def decode_refresh(self, token:str):
        try:
            load = jwt.decode(token, self.SECRETKEY, algorithms=[self.ALGORITHM])
            if load["scope"] == "refresh_token":
                email =  load["sub"]
                return email
            else:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        

    async def get_current_user(self, token:str = Depends(aut_scheme), db :Session = Depends(get_db)):
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            load = jwt.decode(token,self.SECRETKEY,algorithms=[self.ALGORITHM])
            if load["scope"] == "access_token":
                email = load["sub"]
                if email is None:
                    raise exception
            else:
                raise exception
        except JWTError as e:
            raise exception
        user = await rep_users.get_user_by_email(email, db)
        if user is None:
            raise exception
        return user
    
auth_service = Auth()




















































































