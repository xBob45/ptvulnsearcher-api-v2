import os
import psycopg2
from dotenv import load_dotenv

load_dotenv('flaskr/.env.api')
key = os.getenv("SECRET_KEY")
database = os.getenv("DATABASE")
user = os.getenv("DB_USER")
host = os.getenv("HOST")
password = os.getenv("PASSWORD")
port = os.getenv("PORT")

SECRET_KEY = 'SECRET_KEY'
SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://%s:%s@%s:%s/%s' % (user, password, host, port, database)
print(SQLALCHEMY_DATABASE_URI)
CACHE_TYPE = 'SimpleCache'
CACHE_DEFAULT_TIMEOUT = 86400 #One day