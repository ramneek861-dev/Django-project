# -*- coding: utf-8 -*-
"""
Created on Tue Mar 26 14:40:09 2024

@author: DELL
"""

from urllib.parse import urlparse
import pandas as pd

def extract_website(link):
    parsed_url = urlparse(link)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return parsed_url.path.split('/')[0]

# Example usage:
link = "nexusnovus.com"
website = extract_website(link)
print(website)  # Output: www.example.com
result='Not Phishing'

df = pd.read_csv('phishing_site_urls.csv',engine="python")
dff=df['URL']
df.columns=df.iloc[0,:]
df=df.iloc[1:,:]
for x in dff:
    if website in x :
        result='Phishing website'
        break
print("Result",result)