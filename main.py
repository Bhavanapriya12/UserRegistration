from fastapi import FastAPI, HTTPException, Depends
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from models import User
from sqlalchemy.orm import Session
from database import SessionLocal,engine
from fastapi.middleware.cors import CORSMiddleware
import models
from pydantic import BaseModel,EmailStr,Field
import secrets
from fastapi.security import OAuth2PasswordBearer,oauth2

app = FastAPI()


origins =[
    "http://localhost",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


models.Base.metadata.create_all(bind=engine)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

secret_key=secrets.token_urlsafe(32)

SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class UserCreate(BaseModel):
    email: EmailStr
    password:str=Field(min_length=10)
    reenterpassword:str=Field(min_length=10)


class UserLogin(BaseModel):
    email:EmailStr
    password:str


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.post("/signup/")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password)
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
         raise HTTPException(status_code=400, detail="user already exists")
    new_user = User(email=user.email, password=hashed_password)
    db.add(new_user)
    db.commit()

    return {"message": "User created successfully"}


@app.post("/login/")
def login(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if not existing_user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}
