import requests
import shodan
from flask import Flask, render_template, url_for, request
from shodan import Shodan

app = Flask(__name__)


@app.route('/')
def main():  # put application's code here
    return render_template('index.html')

@app.route('/search', methods=['GET','POST'])
def search():  # put application's code here
    target= request.form['ip']
    SHODAN_API_KEY = "rtd3ttigLhJBaPaZLjlmrUExkg7ead5H"
    api = shodan.Shodan(SHODAN_API_KEY)

    dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY
    Data = {}
    try:
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[target]

        # Then we need to do a Shodan search on that IP
        host = api.host(hostIP)
        Data['Ip'] = host['ip_str']
        Data['Organization'] = host.get('org')
        Data['Operating System'] = host.get('OS')
        print ("IP: %s" % host['ip_str'])
        print ("Organization: %s" % host.get('org', 'n/a'))
        print ("Operating System: %s" % host.get('os', 'n/a'))

        # Print all banners
        for item in host['data']:
            #Data['Port'+item['port']]=(item['port'])
            Data['Banner'] = item['data']
            print ("Port: %s" % item['port'])
            print ("Banner: %s" % item['data'])

        # Print vuln information
        for item in host['vulns']:
            CVE = item.replace('!', '')
            Data['Vulnerability'] = item
            print('Vulns: %s' % item)
            exploits = api.exploits.search(CVE)
            for item in exploits['matches']:
                if item.get('cve')[0] == CVE:
                    Data['Description'] = item.get('description')
                    print(item.get('description'))

    except:
        'An error occured'
    print(Data)




    '''
    # Lookup an IP
    ipinfo = api.host(fetchingIp)
    print(type(ipinfo))
    print(ipinfo)
    
    # Search for websites that have been "hacked"
    for banner in api.search_cursor('http.title:"hacked by"'):
        print(banner)
    '''

    return render_template('Result.html',result=Data)


if __name__ == '__main__':
    app.run()
