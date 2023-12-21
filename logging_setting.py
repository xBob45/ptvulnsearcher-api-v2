import logging
import os, sys
import time

timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
logging.basicConfig(level=logging.INFO)  # Sets logging level

#Logger for the Flask part
flask_logger = logging.getLogger('flaskr')
flask_handler = logging.FileHandler('flaskr/logs/%s.log' % timestamp)  # Specify the path for the Flask log file
flask_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
flask_handler.setFormatter(flask_formatter)
flask_logger.addHandler(flask_handler)

#Logger for the database part
database_logger = logging.getLogger('database')
database_handler = logging.FileHandler('database/logs/%s.log' % timestamp)  # Specify the path for the database log file
database_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
database_handler.setFormatter(database_formatter)
database_logger.addHandler(database_handler)

