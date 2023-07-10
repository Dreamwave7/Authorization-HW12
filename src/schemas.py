from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class UserModel(BaseModel):
    username :str = Field(min_length=5, max_length=200)
    email: str
    password: str = Field(min_length=5, max_length = 50)

class UserDB(BaseModel):
    id:int
    username:str
    email:str
    created_at: datetime
    avatar:str

    class Config:
        orm_mode = True


class UserResponse(BaseModel):
    user: UserDB
    detail: str = "User successfully created"

class TokenModel(BaseModel):
    access_token:str
    refresh_token: str
    token_type: str = "bearer"