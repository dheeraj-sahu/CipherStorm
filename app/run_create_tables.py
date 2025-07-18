from app.database import engine, metadata
from app.models import user,profile

metadata.create_all(engine)