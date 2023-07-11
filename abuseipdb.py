import requests
import json
import urllib3
import sys
import time
import csv
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

start_time = time.time()

url = 'https://api.abuseipdb.com/api/v2/check'

headers = {
        'Accept': 'application/json',
        'Key': 'Your Key'
}

MAX_AGE_IN_DAYS = '60'

def usage():
    print("Usage: \n    python script.py [ IP Address | input_file ]")

def get_categories(categories):
    category_mapping = {
        1: '11',
        2: '22',
        3: 'Fraud Orders',
        4: 'DDoS Attack',
        5: 'FTP Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing', 
        8: 'Fraud VoIP',
        9: 'Open Proxy',
        10: 'Web Spam',
        11: 'Email Spam',
        12: 'Blog Spam',
        13: 'VPN IP',
        14: 'Port Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute-Force',
        19: 'Bad Web Bot',
        20: 'Exploited Host',
        21: 'Web App Attack',
        22: 'SSH',
        23: 'IoT Targeted',
    }

    for key, value in category_mapping.items():
        if categories == key:
            return value

def get_reported(reports, report_count):
    print('Last reports:')

    if report_count > 10:
        cnt = 10
    else:
        cnt = report_count

    for i, data in enumerate(reports):
        if i >= cnt:
            break
        tmpTime = datetime.fromisoformat(data['reportedAt'])
        reportedAt_data = tmpTime.strftime('%Y-%m-%d %H:%M:%S')
        categories = data['categories']
        comment = data['comment']

        category = []
        for cate in categories:
            tmp_category = get_categories(cate)
            category.append(tmp_category)
        result_category = ', '.join(category)

        reported = f'Reported at : {reportedAt_data} |  '
        #reported += f'Comment : {comment} |  '
        reported += f'Categories : {result_category}'
        print('*', reported)
        
    print(f'  {cnt} / {report_count} reports\n')


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
    last_report = data.get('lastReportedAt', '')
    report_count = len(reports)

    row = [ip_address, country_code, isp, domain, report_count]
    rows.append(row)

    output = f'IP Address:        {ip_address}\n'
    output += f'Country Code:      {country_code}\n'
    output += f'ISP:               {isp}\n'
    output += f'Domain:            {domain}\n'
    output += f'Report Count:      {report_count}'
    print(output)

    if report_count != 0:
        get_reported(reports, report_count)
    else:
        print('\n')
        
def main():
    start_time = time.time()

    CSV_FILENAME = 'result.csv'
    rows = []

    print("\n Checking...\n")

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
