import os
import requests
import urllib3
from time import sleep
import csv


class DataCollector():
    """Class responsible for database updates."""
    CSV_PATH = 'flaskr/database/allitems.csv'

    def __init__(self):
        pass
    
    def DownloadCSV(self):
        """Function tries to download csv file. Since the MITRE site is under maintenance from time to time after every uncessfull download attempt waits an hour before trying again."""
        while True:
            if os.path.exists(self.CSV_PATH):
                os.remove(self.CSV_PATH)
            try:
                url = 'https://cve.mitre.org/data/downloads/allitems.csv'
                file = requests.get(url)
                if file.status_code == 200:
                    with open (self.CSV_PATH, 'wb') as f:
                        f.write(file.content)
                    break
                else:
                    raise Exception
            except (urllib3.exceptions.MaxRetryError, requests.exceptions.ConnectionError, Exception) as e:
                print("Error occured while downloading the file. Retrying in 1 hour. \n %s" % e)
                sleep(3600)

    def ReadCSV(self):
        """Function reads CVE ID on which subsequent HTTP request on REST API is made."""
        with open (self.CSV_PATH, 'r', encoding='iso8859') as file:
            reader = csv.reader(file)
            
            # This loop skips the csv header
            for i in range(10):
                next(reader) 
            # This loop skips the csv header

            for line in reader:
                yield line[0] #CVE-####-####
                







a = DataCollector()
#a.DownloadCSV()
a.ReadCSV()