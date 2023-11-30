import os
import requests
from requests.exceptions import ConnectionError, JSONDecodeError
from time import sleep
import csv
import psycopg2
from database import connection, cursor

class DataCollector():
    """Class responsible for database updates."""
    CSV_PATH = 'database/allitems.csv'

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
    
    
    def RecordAlreadyExists(self):
        for cve in self.ReadCSV():
            cursor.execute("SELECT EXISTS(SELECT 1 FROM cve WHERE id=%s)", (cve,))
            present = cursor.fetchone()[0]
            if present == True:
                print("%s - Skpipped" % cve)
                continue
            yield cve

    
    def APIRequestResponse(self):
        request_counter = 0
        for cve_id in self.RecordAlreadyExists():
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
                value = response[key]
                return value if value != '*' else default
            except: 
                return default
        
        def JSONDataExtractor_VP(response, default):
            """<JSONDataExtractor> adjusted to handle 'vulnerable product(VP) field'."""
            try:
                return [value if value != '*' else default for value in response['vulnerable_product'][0].split(':')]
            except:
                return [default, default, default, default, default, default]
            
        for response in self.APIRequestResponse():
            data = {
                    'id': JSONDataExtractor(response, 'id', '-'), 
                    'cwe': JSONDataExtractor(response, 'cwe', '-'),  
                    'cvss':JSONDataExtractor(response, 'cvss', '-'), 
                    'cvss_vector':JSONDataExtractor(response, 'cvss-vector', '-'), 
                    'summary':JSONDataExtractor(response, 'summary', '-'), 
                    'vendor':JSONDataExtractor_VP(response, '-')[3], 
                    'product_type':JSONDataExtractor_VP(response, '-')[2].upper(), 
                    'product_name':JSONDataExtractor_VP(response, '-')[4], 
                    'version':JSONDataExtractor_VP(response, '-')[5], 
                    }
            yield data
    
    def InsertToDB(self):
        try:
            for record in self.ParseAPIResponse():
                print(record)
                cursor.execute("INSERT INTO cve(id,cwe,cvss,cvss_vector,summary) VALUES(%s,%s,%s,%s,%s)", (record['id'], record['cwe'], record['cvss'],record['cvss_vector'], record['summary']))
                cursor.execute("INSERT INTO vendor(vendor,product_type,product_name,version) VALUES(%s,%s,%s,%s)", (record['vendor'], record['product_type'], record['product_name'],record['version']))
                connection.commit()
                print("%s -> OK" % record['id'])
        except Exception as e:
            print("Error occured. \n %s" %e)
        finally:
            cursor.close
            connection.close()
        
a = DataCollector()
a.InsertToDB()
