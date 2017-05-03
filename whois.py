import csv
import socket
import sys
import getopt


def read_ipv4_addr_space_csv():
    with open('ipv4-address-space.csv') as csvfile:
        d = [row for row in csv.DictReader(csvfile)]
        dict = {}
        for row in d:
            dict[row['Prefix']] = row['WHOIS']
        return dict


dict = read_ipv4_addr_space_csv()

def whoisurls(prefix):
    return dict[prefix.zfill(3) + '/8']

def whois(ip):
    url = whoisurls(ip.split('.')[:1][0])
    req = {'whois.ripe.net': '-V Md5.2 ' + ip,
           'whois.arin.net': 'z ' + ip
           }.get(url, '-h')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostip = socket.gethostbyname(url)
    s.connect((hostip, 43))
    s.send((req + '\r\n').encode('utf-8'))

    data = ''
    doRecv = True
    while doRecv:
        chunk = s.recv(2048)
        if not chunk:
            doRecv = False
        data += chunk.decode('utf-8')

    print(data)


print("len: ", len(dict))

print('number of arguments: ', len(sys.argv))
print('arguments: ', str(sys.argv))

args = sys.argv[1:]

opts, args = getopt.getopt(args, "")

print('args: ', args)

for req in args:
    print(req)
    whois(req)
