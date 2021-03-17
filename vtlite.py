from tqdm import tqdm
import time, requests
import re

uniqueHashes = []

for f1 in glob.glob("*.log"):
    with open(f1, 'r') as f:
        for line in f:
            sha256 = re.findall(r"([a-fA-F\d]{64})", line)
            #domain = re.findall(domain_regex, line)
            #print (domain)
            if len(sha256) == 1:
                uniqueHashes.append(sha256[0])

uniqueHashes = list(set(uniqueHashes))
apikey = "c9dd5123e30d870068aea77dc1293b32bd2ce83bec9c857d74aef0112a275957"
uagent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"

def getans(hashin):
    answers = {}
    for h in hashin:
        try:
            headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": uagent}
            params = {'apikey': apikey, 'resource': h}
            response = requests.post('https://www.virustotal.com/vtapi/v2/domain/report', params=params, headers=headers)
            jsonResponse = response.json()
            if jsonResponse['response_code'] == 1:
                answers[h] = (str(jsonResponse['positives'])+ '/' +str(jsonResponse['total']))
            else:
                answers[h] = '0'+ '/' +str(jsonResponse['total'])
        except Exception as err:
            answers[h] = 'Error'
    return answers

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

for c in chunks(uniqueHashes, 4):
    ansdict = (getans(c))
    buff = []
    for ans in ansdict.keys():
        print ("{} - {}".format(ans, ansdict[ans]))
    print ("\n(+) Sleeping 60 secs")
    for i in tqdm(range(61)):
        time.sleep(1)
