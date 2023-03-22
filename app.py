# -*- coding: utf-8 -*-
"""BE Proj.ipynb
<h1> Suspicious Link Detection</h1>
"""


import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import re
import nltk



############## Model 1 new########################
import joblib
import numpy as np

import re
#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

from urllib.parse import urlparse

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


def count_dot(url):
    count_dot = url.count('.')
    return count_dot


def count_www(url):
    url.count('www')
    return url.count('www')



def count_atrate(url):
     
    return url.count('@')




def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')



def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')


def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0
    
    

def count_https(url):
    return url.count('https')



def count_http(url):
    return url.count('http')


def count_per(url):
    return url.count('%')



def count_ques(url):
    return url.count('?')



def count_hyphen(url):
    return url.count('-')



def count_equal(url):
    return url.count('=')



def url_length(url):
    return len(str(url))



#Hostname Length

def hostname_length(url):
    return len(urlparse(url).netloc)




def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0



def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits





def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters



#Importing dependencies
from urllib.parse import urlparse
from tld import get_tld
import os.path

#First Directory Length
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0






def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

def main(url):
    
    status = []
    
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)
      
    status.append(tld_length(tld))
    
    
    

    print(status)
    return status





def get_prediction_from_url(test_url):
    try:

        features_test = main(test_url)
        
        # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
        features_test = np.array(features_test).reshape((1, -1))
        print(features_test)
        # features_test=[0, 1, 2, 0, 0, 3, 0, 0, 0, 1, 0, 0, 1, 0, 73, 34, 0, 3, 61, 10, 3]
        LGB_C = joblib.load('Models/rf_model1.h5')
        

        pred = LGB_C.predict(features_test)

        print(pred)
    
    
        if int(pred[0]) == 0:
            
            res="SAFE"
            return res
        elif int(pred[0]) == 1.0:
            
            res="DEFACEMENT"
            return res
        elif int(pred[0]) == 2.0:
            res="PHISHING"
            return res
            
        elif int(pred[0]) == 3.0:
            
            res="MALWARE"
        return 1
    except Exception as e:
        print("error occurs",e)

##############End  Model 1 new########################



############## Model 2 old########################

def getTokens(input):
    tokensBySlash = str(input.encode('utf-8')).split('/')
    allTokens=[]
    for i in tokensBySlash:
        tokens = str(i).split('-')
        tokensByDot = []
        for j in range(0,len(tokens)):
            tempTokens = str(tokens[j]).split('.')
            tokentsByDot = tokensByDot + tempTokens
        allTokens = allTokens + tokens + tokensByDot
    allTokens = list(set(allTokens))
    if 'com' in allTokens:
        allTokens.remove('com')
    return allTokens

############## End Model 2########################



import requests
from bs4 import BeautifulSoup



from flask import *
import json
app = Flask(__name__)  
@app.route('/')  
def home():
    return render_template("index.html")


@app.route('/news')  
def news():
    return render_template("news2.html")

@app.route('/preventions')
def prevention():
    return render_template("prevention.html")


import joblib
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import csr_matrix


@app.route('/getanswer', methods =["GET", "POST"])
def getrecm():
    if request.method == "POST":
        predictx = request.form.get("mname")
        if not predictx.startswith("http://") and not predictx.startswith("https://"):
            predictx = "http://" + predictx

        url=predictx
        print(predictx)

        


        
        try:
            X_predict = [predictx]
            # Load the serialized vectorizer object from the file
            with open('Models/vectorizer.pkl', 'rb') as f:
                vectorizer = pickle.load(f)

            # Define some new URLs to transform
            new_urls = X_predict

            # Use the loaded vectorizer to transform the new URLs into TF-IDF format
            new_urls_tfidf = vectorizer.transform(new_urls)

            # Print the transformed URLs
            X_predict=new_urls_tfidf.toarray()
            print(new_urls_tfidf.toarray())
            print("****")
            print(X_predict)


            # load the saved model
            clfsm = joblib.load('Models/rf_model2.h5')
            y_Predict = clfsm.predict(X_predict)
            #print(y_Predict)

            ## for new model
            y_Predict1= get_prediction_from_url(url)
            print(url)
            try:
                page = requests.get(url)
                soup = BeautifulSoup(page.content, "html.parser")
                

                final_url = page.url
                # serving_ip = page.raw._connection.sock.getpeername()[0]
                serving_ip=123
                status_code = page.status_code
                body_length = len(page.content)
                headers = json.dumps(dict(page.headers))
                meta_tags = soup.find_all("meta")
                arr=[y_Predict[0],url,status_code,body_length, headers,  meta_tags,y_Predict1]

            except:
                
                arr=[y_Predict[0],url,'NA','NA', 'NA',  'NA',y_Predict1]


                

            

            # url_details=f"Final URL: {final_url}<br>Serving IP Address: {serving_ip}<br>Status Code: {status_code}<br>Body Length: {body_length} B<br>Headers:<br>{headers}<br>Meta Tags:<br>{meta_tags}"

           
            # return y_Predict[0]+" <br>"+url_details
            return render_template("result2.html",url_details=arr)

        except Exception as e:
            print(e)
            return ("error")


if __name__ == '__main__':  
   app.run(debug = True)  