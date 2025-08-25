# -*- coding: utf-8 -*-
"""
Created on Thu Mar 14 13:32:39 2024

@author: Hp
"""

import os
import time
import json
import virustotal3.core

#API_KEY = os.environ['d6e8ddc0f68b12f65e414433c94e36bf26892c600e68727f13dbf68947242ad1']
API_KEY='68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b'
vt = virustotal3.core.Files('68fa79f6b4f59f33ad6b6a481f5bb131ff760244485bc380fe11aeb7a138cd8b')

response = vt.upload('file.py')
analysis_id = response['data']['id']
print('Analysis ID: {}'.format(analysis_id))
results = virustotal3.core.get_analysis(API_KEY, analysis_id)
status = results['data']['attributes']['status']

print('Waiting for results...')
while 'completed' not in status:
    results = virustotal3.core.get_analysis(API_KEY, analysis_id)
    status = results['data']['attributes']['status']
    print('Current status: {}'.format(status))
    time.sleep(10)

results = virustotal3.core.get_analysis(API_KEY, analysis_id)
#print(json.dumps(results, indent=4, sort_keys=True))
k=json.dumps(results, indent=4, sort_keys=True)
print(k[0])
#return HttpResponse(results)
k=json.dumps(results, indent=4, sort_keys=True)
import json
s=json.loads(k)
res=s["data"]["attributes"]["results"]
import pandas as pd
df = pd.DataFrame(res)
df=df.transpose()
df=df.reset_index()
k1=['Sophos','StopBadware','Lumu','Netcraft','NotMining','AutoShun','Cyan']
print(k1)
df.columns
df.rename(columns = {'index':'antivirus'}, inplace = True)
df =df[(df.antivirus !='Sophos') & (df.antivirus !='Netcraft') & (df.antivirus !='StopBadware') & (df.antivirus !='Lumu') & (df.antivirus !='NotMining') & (df.antivirus !='AutoShun') & (df.antivirus !='Cyan')   ]
l=[]
for j,i in zip(df.iloc[:,1],df.iloc[:,0]):
    print([i,j])
    l.append([i,j])
        
