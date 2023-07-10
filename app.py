from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from pydantic import BaseModel

from auth import *
from db import *

app = FastAPI()
hash_handler = Hash()

class UserModel(BaseModel):
    username:str
    password:str


@app.post("/signup")
async def signup(body:UserModel, db:Session = Depends(get_db)):
    exist_user = db.query(User).filter(User.email == body.username).first()
    if exist_user:
        raise ValueError
    new_user = User(email = body.username, password = hash_handler.get_password_hash(body.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"new_user":new_user.email}


@app.post("/login")
async def login(body: OAuth2PasswordBearer = Depends(), db:Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.username).first()
    if user is None:
        raise ValueError
    if not hash_handler.verify_password(body.password, user.password):
        raise ValueError
    
    access_token = await create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type":"bearer"}

@app.get("/")
async def root():
    return {"message":"hello python"}


@app.get("/secret")
async def read_item(current_user:User = Depends(get_current_user)):
    return {"message": "secret router", "owner": current_user.email}






































