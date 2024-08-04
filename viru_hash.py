"""
File: viru_hash.py
Author: Santhosh Kumar Kuppan
Date: 04-Aug-2024
Description: #viru_hash part of  #mr_viru tool to check the reputation of the file hash IOCs using VT V3 api and obtain the result in csv.
pre-requisites: python requests and pandas modules, virustotal API key, file hashes to check.
"""
import requests
import pandas as pd
#create a file hash.txt and add your iocs to check 
with open('hash.txt', 'r') as file:
    hash_input = [line.rstrip('\n') for line in file]
data_append=[]
for hash in hash_input:     
    hash=hash
    url=f"https://www.virustotal.com/api/v3/files/{hash}"
    api="your api key here"
    headers = {"accept": "application/json", "x-apikey":api }
    response = requests.get(url, headers=headers)
    hash_response=response.json()
    try:
        malicious=hash_response['data']['attributes']['last_analysis_stats']['malicious']
        suspicious=hash_response['data']['attributes']['last_analysis_stats']['suspicious']
        undetected=hash_response['data']['attributes']['last_analysis_stats']['undetected']
        Risk_score=f'{malicious}/{malicious+undetected}'
        
    except:
        malicious="value not found"
        suspicious="value not found"
    try:
        known_distributer=hash_response['data']['attributes']['known_distributors']
    except:
        known_distributer="value not found"
    try:
        confidence=hash_response['data']['attributes']['sandbox_verdicts']['Zenbox']['confidence']
        malwarename=hash_response['data']['attributes']['sandbox_verdicts']['Zenbox']['malware_names'][0]
        
    except:
        confidence="confidence score not found"
        malwarename="malware name not found"
    try:
        verdict=hash_response['data']['attributes']['sandbox_verdicts']['Zenbox']['malware_classification']
    except:
        verdict="verdict undefined"
    try:
        md5=hash_response['data']['attributes']['md5']
        sha1=hash_response['data']['attributes']['sha1']
        sha256=hash_response['data']['attributes']['sha256']
    except:
        md5="md5 value not found"
        sha1="sha1 value not found"
        sha256="sha256 value not found"
    try:
        signature=hash_response['data']['attributes']['signature_info']['verified']
        product_name=hash_response['data']['attributes']['signature_info']['product']
    except:
        signature="signature info not found"
        product_name="product name not found"
            
    data_dict=dict(hash=hash, md5=md5,sha1=sha1,sha256=sha256,malicious=malicious, suspicious=suspicious, Risk_score=Risk_score,confidence=confidence,verdict=verdict,malwarename=malwarename, signature=signature,known_distributer=known_distributer)
    data_append.append(data_dict)
final_out=pd.DataFrame.from_records(data_append)
final_out.to_csv('viru_hash.csv', index=False)  
print(f"total hashes",{len(hash_input)})
