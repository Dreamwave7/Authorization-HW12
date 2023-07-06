from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLKEY = "postgresql+psycopg2://dkwvkeys:aD0Tydu8H8DSKRQKPMEIAVSLcKK-a6CM@tyke.db.elephantsql.com/dkwvkeys"

engine = create_engine(SQLKEY,  connect_args={"check_same_thread": False})

session = sessionmaker(autoflush=False, autocommit = False, bind=engine)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer(), primary_key=True)
    email = Column(String(200), nullable= False, unique=True)
    password = Column(String(200),nullable=False)





Base.metadata.create_all(bind=engine)

def get_db():
    db = session()
    try:
        yield db
    finally:
        db.close()





























































