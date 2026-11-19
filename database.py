from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from backend.app.config import DATABASE_URL

# SQLite connect_args ensures thread safety for multiple requests
engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency that provides a database session to API routes and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
