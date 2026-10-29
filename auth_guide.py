import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import jwt

# Загружаем переменные окружения из файла .env
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key-for-safety")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_token(data: dict, secret: str = SECRET_KEY) -> str:
    return jwt.encode(data, secret, algorithm="HS256")

def decode_token(token: str, secret: str = SECRET_KEY) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"])
