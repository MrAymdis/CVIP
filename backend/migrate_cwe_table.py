import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import engine, Base
from app.models.cwe import CWE


def migrate_cwe_table():
    print("Dropping existing cwes table...")
    CWE.__table__.drop(engine)
    
    print("Creating new cwes table with updated schema...")
    Base.metadata.create_all(bind=engine)
    
    print("CWE table migration completed successfully!")


if __name__ == "__main__":
    migrate_cwe_table()
