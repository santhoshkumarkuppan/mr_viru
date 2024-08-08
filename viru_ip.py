import requests
import pandas as pd
import re
#create a file hash.txt and add your iocs to check 
with open('ip.txt', 'r') as file:
    ip_input = [line.rstrip('\n') for line in file]
data_append=[]
for ip in ip_input:     
    ip=ip
    ip_reg=re.search("(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)", ip)
    if ip_reg:
        malicious="private IP range"
        suspicious="private IP range"
        undetected="private IP range"
        Risk_score="private IP range"
        country="private IP range"
        owner="private IP range"
        asn="private IP range"
    else:
        req_url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        api="your API key here"
        headers = {"accept": "application/json", "x-apikey":api }
        response = requests.get(req_url, headers=headers)
        ip_response=response.json()
        try:
            malicious=ip_response['data']['attributes']['last_analysis_stats']['malicious']
            suspicious=ip_response['data']['attributes']['last_analysis_stats']['suspicious']
            undetected=ip_response['data']['attributes']['last_analysis_stats']['undetected']
            harmless=ip_response['data']['attributes']['last_analysis_stats']['harmless']
            Risk_score=f'{malicious} out of {malicious+undetected+suspicious+harmless}'
            Risk=malicious+suspicious
            if Risk==0:
                verdict="benign"
            elif Risk<=4:
                verdict="suspicous"
            else:
                verdict="malicious"
                        
        except:
            malicious="value not found"
            suspicious="value not found"
            undetected="value not found"
            harmless="value not found"
            Risk_score="Risck score not found"
            verdict="verdict not found"
        try:
            country=ip_response['data']['attributes']['country']
            owner=ip_response['data']['attributes']['as_owner']
            asn=ip_response['data']['attributes']['asn']  
        except:
            country="country info not found"
            owner="owner info not found"
            asn="asn not found"
    data_dict=dict(ip=ip,country=country,owner=owner,asn=asn,Risk_score=Risk_score,verdict=verdict)
    data_append.append(data_dict)
    final_out=pd.DataFrame.from_records(data_append)
    final_out.to_csv('viru_ip.csv', index=False)  
print(f"total IP checked",{len(ip_input)})   
