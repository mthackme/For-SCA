import requests
import xml.etree.ElementTree as ET
import datetime
import requests
from bs4 import BeautifulSoup
import re
import csv

class MavenDependency:

    def __init__(self, sha1_checksum):
        self.sha1_checksum = sha1_checksum
        self.group_id = None
        self.artifact_id = None
        self.license = None
        self.current_version = None
        self.current_version_timestamp = None
        self.current_version_datetime = None
        self.current_version_age = None
        self.current_version_cve = []
        self.current_version_severity = []
        self.latest_version = None
        self.latest_version_timestamp = None
        self.latest_version_datetime = None
        self.latest_version_age = None
        self.latest_version_cve = []
        self.latest_version_severity = []
        self.eol = None
        self.reference = None
        self.recommendation = None
        self.numFound = None


    def fetch_metadata(self):
        metadata_url = f"https://search.maven.org/solrsearch/select?q=1:{self.sha1_checksum}&core=gav&rows=20&wt=xml"
        response = requests.get(metadata_url)
        root = ET.fromstring(response.content)

        ## Getting numFound result ##
        numFound = root.find(".//result").attrib['numFound']
        self.numFound = int(numFound)

        if self.numFound == 1:

            self.group_id = root.find(".//str[@name='g']").text
            self.artifact_id = root.find(".//str[@name='a']").text
            self.current_version = root.find(".//str[@name='v']").text
            self.current_version_timestamp = root.find(".//long[@name='timestamp']").text

            timestamp_seconds = int(self.current_version_timestamp[:-3])
            self.current_version_datetime = datetime.datetime.fromtimestamp(timestamp_seconds)

            #calculate the current version to current date
            current_date = datetime.datetime.now()
            current_time_diff = current_date - self.current_version_datetime

            # Calculate the age of the current version in years and months
            current_version_age_years = current_time_diff.days // 365
            current_version_age_months = (current_time_diff.days % 365) // 30
            self.current_version_age = current_version_age_years + (current_version_age_months / 10)

                
    def fetch_latest_version(self):

        #print(self.sha1_checksum)

        if self.numFound == 1:

            url = f'https://repo1.maven.org/maven2/{self.group_id.replace(".", "/")}/{self.artifact_id}/maven-metadata.xml'
            response = requests.get(url)
            root = ET.fromstring(response.content)

            #print(url)
            #print(self.group_id)

            if root.find('.//versioning/latest'):
            
                self.latest_version = root.find('.//versioning/latest').text

            else:
                
                latest_version_last = root.find('.//versioning/versions')
                self.latest_version = latest_version_last[-1].text
                
            #print(self.latest_version)

            self.latest_version_timestamp = root.find('.//versioning/lastUpdated').text
            self.latest_version_datetime = datetime.datetime.strptime(self.latest_version_timestamp, '%Y%m%d%H%M%S')

            #calculate the Latest Version to Current date
            latest_date = datetime.datetime.now()
            latest_time_diff = latest_date - self.latest_version_datetime

            # Calculate the age of the current version in years and months
            latest_version_age_years = latest_time_diff.days // 365
            latest_version_age_months = (latest_time_diff.days % 365) // 30
            self.latest_version_age = latest_version_age_years + (latest_version_age_months / 10)

    def save_to_csv(self, filename="testingmo.csv"):     

        print(f"SHA1: {self.sha1_checksum}")
        # print(f"Group ID: {self.group_id}")
        # print(f"Artifact ID: {self.artifact_id}")
        # print(f"License: {self.license}")
        # print(f"Current Version: {self.current_version}")
        # print(f"Current Version Published Date: {self.current_version_datetime}")
        # print(f"Current version age(years): {self.current_version_age} years")
        # print(f"Latest version: {self.latest_version}")
        # print(f"Latest version Published Date: {self.latest_version_datetime}")
        # print(f"Latest version Age(years): {self.latest_version_age} years")
        # print(f"EOL: {self.eol}")
        print(f"Vulnerabilities of Current Version: {', '.join(self.current_version_cve)}")
        print(f"Severity of Current Version: {', '.join(self.current_version_severity)}")
        print(f"Vulnerabilities in Latest Version: {self.latest_version_cve}")
        print(f"Severity of Latest Version: {self.latest_version_severity}")
        # print(f"References: {self.reference}")
        # print(f"Recomendations: {self.recommendation}")

        if self.numFound == 1:
            data = {
                'SHA1': self.sha1_checksum, 'Group ID': self.group_id, 'Artifact ID': self.artifact_id, 'License': '', 'Current Version': self.current_version, 'Current Version Published Date': self.current_version_datetime, 'Current Version Age (years)': f"{self.current_version_age} years", 'Latest Version': self.latest_version, 'Latest Version Published Date': self.latest_version_datetime, 'Latest Version Age (years)': f"{self.latest_version_age} years", 'Vulnerabilities of Current Version': f"{self.current_version_cve}", 'Severity of Current Version': f"{self.current_version_severity}", 'Vulnerabilities in Latest Version': f"{self.latest_version_cve}", 'Severity of Latest Version': f"{self.latest_version_severity}", 'References': f"{self.reference}", 'Recomendations': f"{self.recommendation}"}

            with open(filename, 'a', newline='') as csvfile:
                # fieldnames = data.keys()
                writer = csv.DictWriter(csvfile, fieldnames=headerList)
                # writer.writeheader()
                writer.writerow(data)

        else:
            data = {
                'SHA1': self.sha1_checksum, 'Group ID': 'None', 'Artifact ID': 'None', 'License': 'None', 'Current Version': 'None', 'Current Version Published Date': 'None', 'Current Version Age (years)': 'None', 'Latest Version': 'None', 'Latest Version Published Date': 'None', 'Latest Version Age (years)': 'None', 'Vulnerabilities of Current Version': 'None', 'Severity of Current Version': 'None', 'Vulnerabilities in Latest Version': 'None', 'Severity of Latest Version': 'None', 'References': 'None', 'Recomendations': 'None'}

            with open(filename, 'a', newline='') as csvfile:
                # fieldnames = data.keys()
                writer = csv.DictWriter(csvfile, fieldnames=headerList)
                # writer.writeheader()
                writer.writerow(data)
    

    def get_cve_severity(self):

        if self.numFound == 1:

            def get_value_from_html(url):
                response = requests.get(url)
                href_value_list = []
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    href_element_list = soup.find_all('a', {'data-snyk-test': 'vuln table title'})
                    for href_element in href_element_list:
                        if href_element and 'href' in href_element.attrs:
                            href_value = href_element['href']
                            href_value_list.append(href_value)
                            # print(href_value)
                return href_value_list

            def get_cve_from_html(cveresponse):
                if cveresponse.status_code == 200:
                    cvesoup = BeautifulSoup(cveresponse.content, 'html.parser')
                    cveid_element = cvesoup.find('a', {'id': re.compile(r'^CVE-\d{4}-\d{5}$')})
                    if cveid_element:
                        cveid_value = cveid_element['id']
                        self.latest_version_cve = cveid_value
                        # print(self.latest_version_cve)
                        return cveid_value
                return None

            def get_severity_from_snyk(sevresponse):
                if sevresponse.status_code == 200:
                    sevsoup = BeautifulSoup(sevresponse.content, 'html.parser')
                    severity_element = sevsoup.find('span', class_='vue--badge__text')
                    if severity_element:
                        severity_value_snyk = severity_element.text
                        # print(severity_value_snyk)
                        return severity_value_snyk
                    return None
                
            def get_severity_from_nvd(sevresponse):
                if sevresponse.status_code == 200:
                    sevsoup = BeautifulSoup(sevresponse.content, 'html.parser')
                    severity_element = sevsoup.find('a', id='Cvss3NistCalculatorAnchor')
                    if severity_element:
                        severity_value_nvd = severity_element.text
                        # print(severity_value_nvd)
                        self.latest_version_severity = severity_value_nvd
                        return severity_value_nvd
                    return None


            # Replace with the URL you want to request
            url = f'https://security.snyk.io/package/maven/{self.group_id}:{self.artifact_id}/{self.latest_version}'
            print(url)
            value_list = get_value_from_html(url)
            cve_list = []
            for value in value_list:
                url1 = 'https://security.snyk.io/' + value
                serveresponse = requests.get(url1)
                cvevalue = get_cve_from_html(serveresponse)
                if cvevalue:
                    cve_list.append(cvevalue)
                    url2 = 'https://nvd.nist.gov/vuln/detail/' + cvevalue
                    nvdresponse = requests.get(url2)
                    severity_nvd = get_severity_from_nvd(nvdresponse)
                    # print(severity_nvd)
                    ##get severity from NVD##

                else:
                    cve_list.append(value)
                    severity_value = get_severity_from_snyk(serveresponse).strip()
                    # print(severity_value)
                    ##get severity from snyk##
                           

if __name__ == '__main__':

### Create This for header once"
    filename="testingmo.csv"
    headerList = ['SHA1', 'Group ID', 'Artifact ID', 'License', 'Current Version', 'Current Version Published Date', 'Current Version Age (years)', 'Latest Version', 'Latest Version Published Date', 'Latest Version Age (years)', 'Vulnerabilities of Current Version', 'Severity of Current Version', 'Vulnerabilities in Latest Version', 'Severity of Latest Version', 'References', 'Recomendations']
        
    with open(filename, 'w', newline='') as csvfile:
        # fieldnames = data.keys()
        writer = csv.DictWriter(csvfile, fieldnames=headerList)
        writer.writeheader()


## Parsing Data from XML file
    tree = ET.parse('dependency-check-report.xml')
    root = tree.getroot()

    dependencies = root.find('{*}dependencies')
    dependencylist = dependencies.findall("{*}dependency")

    sha1list = []
    

    for dependency in dependencylist:

        sha1list.append(dependency.find('{*}sha1').text)
        
        vulns = dependency.find('{*}vulnerabilities')
        if vulns is not None:
                
                vulnlist = vulns.findall("{*}vulnerability")
        else:
                vulnlist = []
                # print("No VUlnerability Found")

        for vuln in vulnlist:
            nameElement = vuln.find("{*}name")
            nameVuln = nameElement.text if nameElement is not None else None
            severityElement = vuln.find("{*}severity")
            severity = severityElement.text if severityElement is not None else None
            cve_entry = f"CVE: {nameVuln}, SEVERITY: {severity}"

        # print(f"CVE:{nameVuln}, Severity: {severity}")
    
    for sha1 in sha1list:
        
        #     ### call all method
        dependency = MavenDependency(sha1)
        dependency.fetch_metadata()
        dependency.fetch_latest_version()
        dependency.current_version_cve.append(nameVuln)
        dependency.current_version_severity.append(severity)
        dependency.get_cve_severity()
        dependency.save_to_csv()
        # #dependency.printCVE()

