from urllib.parse import urlparse,urljoin
import requests
import re
import whois
import pandas as pd
from ssl_checker import SSLChecker
SSLChecker = SSLChecker()
from constants import shortening_services, ccTLD
import datetime
from bs4 import BeautifulSoup

#PHISH = 0
#LEGIT = 1

#not needed for now
#url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')




#FEATURES EXTRACTED FROM THE URL


#getting the domain
def getDomain(url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.",domain):
        domain = domain.replace("www.","")
    return domain


#checking if the url has an IP
def havingIP(url):
    
    ipv4_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ipv6_pattern = r'\b[0-9a-fA-F:]+\b'

    ipv4_match = re.search(ipv4_pattern, url)
    ipv6_match = re.search(ipv6_pattern, url)

    if ipv4_match or ipv6_match:
        ip = 0
    else:
        ip = 1

    
    return ip


#checking for multiple domains
def multi_domain(url):

    domain = urlparse(url).netloc
    for i in ccTLD:
        domain = domain.replace(i,'')
    req = domain.split('.')
    if len(req) <= 2:
        multi_domain = 1
    elif len(req) == 3:
        multi_domain = 0.5
    else:
        multi_domain = 0
    
    return multi_domain    


#check for '@'
def have_at(url):
    if '@' in url:
        have_at = 0
    else:
        have_at = 1
    return have_at


#checking length
def length(url):
    if len(url)<54:
        length = 1
    elif len(url)>=54 and len(url)<=74:
        length = 0.5
    else:
        length = 0
    return length


#checking for redirects
def redirect(url):
    if url.rfind('//') > 6:
        redirect = 0
    else:
        redirect = 1
    return redirect


#checking for hypens
def hyphen(url):
    if '-' in url:
        hyphen = 0
    else:
        hyphen = 1
    return hyphen


#checking domain age
def domain_age(domain):       
    try:

        if (type(domain.expiration_date) == list):
            time_periord = abs(( domain.expiration_date[0] - domain.creation_date).days)/365
        elif (type(domain.expiration_date) == datetime.datetime):
            time_periord = abs(( domain.expiration_date - domain.creation_date).days)/365
        else:
            return 0
        
        if time_periord >=1 :
            return 1
        else:
            return 0
    except:
        return 0


#checking for shortening services
def short_url(url):

    for pattern in shortening_services:
        match = re.search(pattern, url)
        if match:
            return 0
        else:
            return 1


#checking for certificate
def check_cert(url):
    
    try:
        args = {
            'hosts': [url]
        }

        y = SSLChecker.show_result(SSLChecker.get_args(json_args=args))

        replacements = [("null",'"null"'), ('false','"False"'), ('true','"True"')]

        for org, cng in replacements:
            if org in y:
                y = y.replace(org, cng)

        info = eval(y)
        
        if info[url]['cert_valid'] == 'True':
            return 1
        else:
            return 0
    except:
        return 0


#FEATURES EXTRACTED FROM THE HTML/JAVASCRIPT


#number of forwards
def forwarding(resp):
    if len(resp.history) <= 2:
        return 1
    else:
        return 0


#items pointing to the same domains
def request_url(url, soup):
    
    total_objects = 0
    external_objects = 0
    
    for tag in soup.find_all(['img', 'video', 'audio', 'script', 'link']):
        if tag.has_attr('src') or tag.has_attr('href'):
            tag_url = tag.get('src') or tag.get('href')
            full_url = urljoin(url, tag_url)
            parsed_url = urlparse(full_url)

            
            if parsed_url.netloc != '' and parsed_url.netloc != urlparse(url).netloc:
                external_objects += 1
            
            total_objects += 1

    if total_objects == 0:
        return 1

    percentage_external = (external_objects / total_objects) * 100

    if percentage_external < 22:
        return 1
    elif 22 <= percentage_external < 61:
        return 0.5
    else:
        return 0


#references to the same domain
def anchor_urls(url, soup):
    
    total_anchors = 0
    external_anchors = 0
    
    base_url_parsed = urlparse(url)
    
    try:
        for a_tag in soup.find_all('a', href=True):
            tag_url = a_tag['href']
            full_url = urljoin(url, tag_url)
            parsed_url = urlparse(full_url)
            
        
            if parsed_url.netloc != base_url_parsed.netloc or parsed_url.fragment:
                external_anchors += 1
            
            total_anchors += 1

        if total_anchors == 0:
            return 1

        percentage_external_anchors = (external_anchors / total_anchors) * 100

        if percentage_external_anchors < 31:
            return 1
        elif 31 <= percentage_external_anchors <= 67:
            return 0.5
        else:
            return 0
    except:
        return 0




#MAKING THE DATASHEET
def get_features(url,status):

    url = str(url)
    features = []
    
    #URL BASED FEATURES(8)
    features.append(getDomain(url))
    features.append(havingIP(url))
    features.append(multi_domain(url))
    features.append(have_at(url))
    features.append(length(url))
    features.append(redirect(url))
    features.append(hyphen(url))
    features.append(short_url(url))
    

    #DNS BASED FEATURES(3)
    dns = 1
    try:
        domain = whois.whois(urlparse(url).netloc)
        if domain.domain_name == 'null':
            dns = 0
    except:
        dns = 0

    features.append(dns)
    features.append(0 if dns == 0 else check_cert(urlparse(url).netloc))
    features.append(0 if dns == 0 else domain_age(domain))


    #HTML BASED FEATURES(3)
    try:
        resp = requests.get(url, timeout=1)
        soup = BeautifulSoup(resp.text, 'html.parser')
    except:
        resp = ''
        
    features.append(0 if resp == '' else forwarding(resp))
    features.append(0 if resp == '' else anchor_urls(url, soup))
    features.append(0 if resp == '' else request_url(url, soup))

    
    #STATUS
    features.append(status)
    
    return features



#Loading the Phishing dataset
phishing_data = pd.read_csv("YOUR_PHISH_DATASET_PATH")
phishing_data.columns = ['url']

phish_sample = phishing_data.copy()
phish_sample = phish_sample['url']
#print(phish_sample.head())



#Loading the Benign dataset
legit_data = pd.read_csv("YOUR_BENIGN_DATASET_PATH")
legit_data.columns = ['url']

legit_sample = legit_data.copy()
legit_sample = legit_sample['url']
#print(legit_sample.head())


#Column names for dataframe
column_name = ['domain','have_IP','multi_domain','have_at','length','redirect','hyphen_present','short_url','dns','check_cert','domain_age','forwarding','anchor_urls','request_url','status']




#Extracting Features from Benign dataset
legit_feature = []
label = 1

for i in legit_sample:
    legit_feature.append(get_features(i,label))

legit = pd.DataFrame(legit_feature, columns = column_name)



#Extracting Features from Phishing dataset
phish_feature = []
label = 0

for i in phish_sample:
    phish_feature.append(get_features(i,label))

phish = pd.DataFrame(phish_feature, columns = column_name)



#Merging both the datasets
final_data = pd.concat([legit,phish]).reset_index(drop=True)
final_data.to_csv("PATH_TO_STORE_THE_FINAL_DATASET")
print('Dataset Processed.')