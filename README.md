# NetworkNotification

NetworkNotification is an Python3 based network mapping and notification tool.  The tool periodically scans a local network for live hosts and baisc OS information before logging live hosts in a csv databse.  When new devices are identified (via a unique MAC Address), a notification is sent using Twilio's SMS client.  The existing database can then be viewed via a web browser using bootstrap and javascript.  
