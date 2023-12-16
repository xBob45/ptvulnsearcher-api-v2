import os
import psycopg2
from dotenv import load_dotenv

load_dotenv('database/.env.database')
database = os.getenv("DATABASE")
user = os.getenv("DB_USER")
host = os.getenv("HOST")
password = os.getenv("PASSWORD")
port = os.getenv("PORT")

connection = psycopg2.connect(database='ptvulnsearcher', user='postgres', host='localhost', password='postgres', port=5432)
cursor = connection.cursor()