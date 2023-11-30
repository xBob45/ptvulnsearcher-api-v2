import psycopg2

connection = psycopg2.connect(database='ptvulnsearcher', user='postgres', host='localhost', password='postgres', port=5432)
cursor = connection.cursor()