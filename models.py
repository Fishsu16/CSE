# models.py
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_async_engine(DATABASE_URL, echo=True)
Base = declarative_base()
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    otp_secret = Column(String(32), nullable=False)
    user_sk = Column(String, nullable=True)
    user_pk = Column(String, nullable=True)
    #kyber_sk = Column(String, nullable=True)
    #kyber_pk = Column(String, nullable=True)
    #dilithium_sk = Column(String, nullable=True)
    #dilithium_pk = Column(String, nullable=True)


async def get_db():
    async with async_session() as session:
        yield session
