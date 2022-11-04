import socket
from random import randint
from random import choice
from datetime import datetime
from parsers import *

# cache using a dictionary
cache = {}

def log(*args):
    print('>>> ', end='')
    print(*args)

def build_packet(hostname):
    packet = bytes()

    # header
    packet += (int.to_bytes(randint(0, 65536), 2, 'big'))

    # flags
    packet += (int.to_bytes(256, 2, 'big'))

    # qdcount
    packet += (int.to_bytes(1, 2, 'big'))
    
    # ancount
    packet += (int.to_bytes(0, 2, 'big'))
    
    # nscount
    packet += (int.to_bytes(0, 2, 'big'))
    
    # arcount
    packet += (int.to_bytes(0, 2, 'big'))
    
    # hostname labels
    for label in hostname.split('.'):

        # length of label
        packet += (int.to_bytes(len(label), 1, 'big'))

        # label
        packet += label.encode()

    # null identifier
    packet += (int.to_bytes(0, 1, 'big'))

    # qtype
    packet += (int.to_bytes(1, 2, 'big'))

    # qclass
    packet += (int.to_bytes(1, 2, 'big'))

    return bytes(packet)
        
def parse_packet(packet):
    parsed = {}

    # header
    parsed['header'] = packet[:2]

    # flags
    parsed['flags'] = packet[2:4]

    # qdcount
    parsed['qdcount'] = int.from_bytes(packet[4:6], byteorder='big')
    
    # ancount
    parsed['ancount'] = int.from_bytes(packet[6:8], byteorder='big')
    
    # nscount
    parsed['nscount'] = int.from_bytes(packet[8:10], byteorder='big')
    
    # arcount
    parsed['arcount'] = int.from_bytes(packet[10:12], byteorder='big')

    # parse body
    parsed['questions'], bp = parse_questions(packet, parsed['qdcount'])
    parsed['answers'], bp = parse_records(packet, parsed['ancount'], bp)
    parsed['nameservers'], bp = parse_records(packet, parsed['nscount'], bp)
    parsed['additionals'], bp = parse_records(packet, parsed['arcount'], bp)

    return parsed
    

def make_dns_req(query, server_ip, server_port=53):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.sendto(query, (server_ip, server_port))
        message, client = udp.recvfrom(1024)
    return message

def pick_nameserver_ip(response):
    # look for nameservers in authority section 
    # and map them to their IPs in additional
    for nameserver in response['nameservers']:
        for additional in response['additionals']:
            if nameserver['addr'] == additional['hostname']:
                return additional['addr']

def resolve_ip(hostname):

    # check if already resolved and in cache
    if hostname in cache:
        cached_answer = cache[hostname]
        # check if cache still valid and return else delete from cache
        if (datetime.now() - cached_answer['timestamp']).seconds < cached_answer['ttl']:
            log("Answer already cached")
            return cached_answer['addr']
        else:
            del cache[hostname]

    # build first query
    query = build_packet(hostname)

    ## ROOT DNS SERVER
    # select a root server
    root_servers = ['198.41.0.4', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241']
    root_ip = choice(root_servers)
    log("Root IP:", root_ip)

    # send request to root server
    root_response = parse_packet(make_dns_req(query, root_ip, 53))

    # look for tld server IP in additional records
    tld_ip = pick_nameserver_ip(root_response)
    log("TLD IP:", tld_ip)


    ## TLD DNS SERVER
    # send query to tld
    tld_response = parse_packet(make_dns_req(query, tld_ip))

    # look for authoritative server IP in additional records
    auth_ip = pick_nameserver_ip(tld_response)
    log('Authoritative IP:', tld_ip)

    # send query to tld
    auth_response = parse_packet(make_dns_req(query, auth_ip))

    # send query to authoritative
    log('Answer Resource Records:')
    print('\t%s%s%s%s' % ('Name'.ljust(15), 'Type'.ljust(10), 'Value'.ljust(18), 'TTL'.ljust(10)))
    for answer in auth_response['answers']:
        print('\t%s%s%s%s' % (answer['hostname'].ljust(15), answer['type'].ljust(10), answer['addr'].ljust(18), str(answer['ttl']).ljust(10)))

    # choose a random answer
    answer = choice(auth_response['answers'])
    log('Server IP:', answer['addr'])

    # timestamp the answer and cache it
    answer['timestamp'] = datetime.now()
    cache[hostname] = answer

    # return resolved IP addr
    return answer['addr']

def get_html(hostname, ip):
    # send GET / request to IP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        # connect on http port 80
        tcp.connect((ip, 80))
        # send GET request
        http_req = 'GET / HTTP/1.1\r\nHost:%s\r\n\r\n' % hostname
        tcp.sendall(http_req.encode())
        # receive HTML response
        return tcp.recv(4096)

if __name__ == '__main__':
    while True:
        # get hostname from stdin
        hostname = input('Hostname > ').strip()

        try:
            # resolve IP address using iterative DNS
            ip = resolve_ip(hostname)
        
            # send http get request and write to file
            file = 'html/%s.html' % hostname
            log("Writing HTML to %s" % file)

            html = get_html(hostname, ip)
            with open(file, 'wb') as f:
                f.write(html)
        except:
            print('Could not resolve hostname')

        print(''.ljust(60, '*'))