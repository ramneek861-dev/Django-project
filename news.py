# -*- coding: utf-8 -*-
"""
Created on Thu Mar  7 19:40:30 2024

@author: Hp
"""
from newsapi import NewsApiClient
import datetime
from datetime import date

# Init
newsapi = NewsApiClient(api_key='9977d45a2873403b88d670b0fca4daa1')


# /v2/everything
json_data = newsapi.get_everything(q='cybersecurity',
                                      from_param=str(date.today()-datetime.timedelta(days=29)),
                                      to=str(date.today()),
                                      language='en',
                                      page_size=18,
                                      page=1,
                                      sort_by='relevancy',)
print(json_data)
