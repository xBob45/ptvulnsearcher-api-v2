import os
import requests
from requests.exceptions import ConnectionError, JSONDecodeError
from time import sleep
import csv
from flaskr.models.cve import db



# PostgreSQL connection should be done like this https://www.datacamp.com/tutorial/tutorial-postgresql-python
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
                print("Downloading . . .")
                file = requests.get(url)
                if file.status_code == 200:
                    with open (self.CSV_PATH, 'wb') as f:
                        f.write(file.content)
                        print("Download complete.")
                    break
                else:
                    raise ConnectionError
            except (ConnectionError, Exception) as e:
                print("Error occured while downloading the file. Retrying in 10 minutes. \n %s" % e)
                sleep(600)

    def ReadCSV(self):
        """Function reads CVE ID on which subsequent HTTP request on REST API is made."""
        with open (self.CSV_PATH, 'r', encoding='iso8859') as file:
            try:
                reader = csv.reader(file)
                
                # This loop skips the csv header
                for i in range(10):
                    next(reader) 
                # This loop skips the csv header

                for line in reader:
                    yield line[0] #CVE-####-####
            except Exception as e:
                print(e)
    
    def APIRequestResponse(self):
        request_counter = 0
        for cve_id in self.ReadCSV():
            if request_counter == 180:
                sleep(60)
                request_counter = 0
            try:
                url = 'https://cve.circl.lu/api/cve/%s' % cve_id  #If no record found returns 'null'.
                api_request = requests.get(url)
                request_counter = request_counter + 1
                if api_request.status_code == 200:
                    try:
                        api_response = api_request.json()
                        if api_response == None:
                            continue
                        yield api_response
                    except (JSONDecodeError, Exception) as e: #From time to time JSONDecodeError Exception occures especially in latest records.
                        continue
                else:
                    raise ConnectionError
            except (ConnectionError, Exception) as e:
                print("Could not resolve the address. \n Record: %s \n Retrying in 30 minutes. \n %s" % (cve_id, e))
                sleep(1800)
                
    def ParseAPIResponse(self):

        def JSONDataExtractor(response, key, default):
            """This function extract JSON data from REST API response."""
            try:
               return response[key]
            except: 
                return default
        
        def JSONDataExtractor_VP(response, default):
            """Overloaded function is adjusted to handle 'vulnerable product(VP) field'."""
            try:
                return response['vulnerable_product'][0].split(':')
            except:
                return [default, default, default, default, default,default]

        for response in self.APIRequestResponse():
            data = {
                    'id': JSONDataExtractor(response, 'id', '-'), 
                    'cwe': JSONDataExtractor(response, 'cwe', '-'),  
                    'cvss':JSONDataExtractor(response, 'cvss', 0.0), 
                    'cvss_vector':JSONDataExtractor(response, 'cvss-vector', '-'), 
                    'summary':JSONDataExtractor(response, 'summary', '-'), 
                    'vendor':JSONDataExtractor_VP(response, '-')[3], 
                    'product_type':JSONDataExtractor_VP(response, '-')[2].upper(), 
                    'product_name':JSONDataExtractor_VP(response, '-')[4], 
                    'version':JSONDataExtractor_VP(response, 0.0)[5], 
                    }
            yield data
    
    def InsertToDB(self):
        try:
            for record in self.ParseAPIResponse():
                db.session.add(record)
                db.session.commit()
        except Exception as e:
            print("Error occured. \n %s" %e)
        finally:
            db.session.close()
        

a = DataCollector()
#a.DownloadCSV()
a.InsertToDB()
