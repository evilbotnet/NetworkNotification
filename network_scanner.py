#!/usr/bin/env python3
from twilio.rest import Client
import nmap
import csv
import os.path
import time

start = time.time()
nm = nmap.PortScanner() # instantiate nmap.PortScanner object
nm2 = nmap.PortScanner()
global macList, ipv4List, hostnameList, vendorList
macList = []
ipv4List = []
hostnameList = []
vendorList = []

def _csvParse(inputfile):

    if os.path.exists(inputfile) == True:
        print("Found existing file. Working with " + inputfile)
        f = open(inputfile)
        csv_file = csv.reader(f, delimiter=',')
        for row in csv_file:
            macList.append(row[0])
            ipv4List.append(row[1])
            hostnameList.append(row[2])
            vendorList.append(row[3])
    else:
        print("No file found. Creating file at " + inputfile)
        with open("networkHosts.csv", "a", encoding='utf8', newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            mac = "Mac Address"
            ipv4 = "IP Address"
            hostname = "Hostname"
            vendor = "Vendor"
            line = (mac, ipv4, hostname, vendor)
            writer.writerow(line)


def _scanner(network, argument):
    _csvParse("networkHosts.csv")
    print("Starting Scan...")
    nm.scan(network, arguments=argument)
    liveHosts = nm.scanstats()['uphosts']
    time = nm.scanstats()['elapsed']
    for host in nm.all_hosts():
        d = {}
        if nm[host]['status']['state'] == 'down':
            pass
        else:
            ipv4 = nm[host]['addresses']['ipv4']
            try:
                mac = nm[host]['addresses']
                mac = mac.get("mac")
                vendor = nm[host]['vendor']
                vendor = list(vendor.values())[0]
            except IndexError as e:
                vendor = "NO VENDOR FOUND"
                mac = "00:00:00:00:00:00"
            hostname = nm[host]['hostnames'][0]['name']

            if mac in macList:
                print("Found previous mac address " + mac)
            else:
                print("Found new mac address " + mac + " Adding to csv.")
                with open("networkHosts.csv", "a", encoding='utf8', newline='') as csv_file:
                    writer = csv.writer(csv_file, delimiter=',')
                    line = (mac, ipv4, hostname, vendor)
                    writer.writerow(line)
                #_sendText(mac, vendor, ipv4, hostname)
                nm2.scan(ipv4, arguments='-O -F -T5')
                print("Running a fast nmap scan on " + ipv4)
                print(nm2.csv(),file=open(mac,'w'))
                d[mac] = ipv4, vendor
                print(d[mac][1])
    _buildTable()
    print("Found " + liveHosts + " hosts in " + time + ".")

def _sendText(mac, vendor, ipv4, hostname):
    # Your Account SID from twilio.com/console
    # Your Auth Token from twilio.com/console
    account_sid = ""
    auth_token = ""
    client = Client(account_sid, auth_token)
    message = client.messages.create(
        to="+15555555555",
        from_="+15555555555",
        body="New device connected: " + hostname + ' ' + mac + ' ' + vendor + ' ' + ipv4)

def _buildTable():
    print("Building Table...")
    csvFile = open('networkHosts.csv')  # enter the csv filename
    csvReader = csv.reader(csvFile)
    csvData = list(csvReader)

    with open('output.html', 'w') as html:  # enter the output filename
        html.write('''<!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.8.1/bootstrap-table.min.css">

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">''')
        html.write('<table data-toggle = "table" data-search = "true">\r')
        r = 0
        for row in csvData:
            if r == 0:
                html.write('\t<thead>\r\t\t<tr>\r')
                for col in row:
                    html.write('\t\t\t<th data-sortable="true">' + col + '</th>\r')
                html.write('\t\t</tr>\r\t</thead>\r')
                html.write('\t<tbody>\r')
            else:
                html.write('\t\t<tr>\r')
                for col in row:
                    html.write('\t\t\t<td>' + col + '</td>\r')
                html.write('\t\t</tr>\r')
            r += 1
        html.write('\t</tbody>\r')
        html.write('</table>\r')

        html.write('''
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.0/jquery.min.js"></script>

    <!-- Latest compiled and minified JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>

    <!-- Latest compiled and minified JavaScript -->
        <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.8.1/bootstrap-table.min.js"></script>
    ''')
    print("Completed!")

_scanner('192.168.1.1/24', '-sn -T5 -v')
end = time.time()
print(end - start)

