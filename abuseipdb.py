import requests
import json
import urllib3
import sys
import time
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

start_time = time.time()

url = 'https://api.abuseipdb.com/api/v2/check'

headers = {
        'Accept': 'application/json',
        'Key': 'Your Key Input'
}

MAX_AGE_IN_DAYS = '60'

def usage():
    print("Usage: \n    python script.py [ IP Address | input_file ]")

def write_csv(filename, rows):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP Address', 'Country Code', 'ISP', 'Domain', 'Report Count(60 Days)'])
        writer.writerows(rows)

def check_abuseIP(ip, rows):
    params = {
        'ipAddress': str(ip),
        'maxAgeInDays': MAX_AGE_IN_DAYS,
        'verbose': True
    }
    response = requests.get(url, headers=headers, params=params, verify=False)
    decoded_response = response.json()
    data = decoded_response.get('data', {})
    ip_address = data.get('ipAddress', '')
    country_code = data.get('countryCode', '')
    isp = data.get('isp', '')
    domain = data.get('domain', '')
    reports = data.get('reports', [])
    report_count = len(reports)

    row = [ip_address, country_code, isp, domain, report_count]
    rows.append(row)0

    output = f'IP Address:    {ip_address}\n'
    output += f'Country Code:  {country_code}\n'
    output += f'ISP:           {isp}\n'
    output += f'Domain:        {domain}\n'
    output += f'Report Count:  {report_count}\n'    
    print(output)

def main():
    start_time = time.time()

    CSV_FILENAME = 'result.csv'
    rows = []

    if len(sys.argv) == 2:
        input_file = sys.argv[1]
        
        if not input_file.endswith('.txt'):
            check_abuseIP(input_file, rows)
        else:
            with open(input_file, 'r') as f:
                lines = f.readlines()
            for line in lines:
                ip = line.strip()
                if ip:
                    check_abuseIP(ip, rows)
            write_csv(CSV_FILENAME, rows)
        print(f'Total Time:    {round((time.time() - start_time), 2)} seconds')

    else:
        usage()
    
if __name__ == '__main__':
    main()
