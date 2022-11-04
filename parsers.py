def parse_hostnames(packet, ptr):
    # parse qname
    hostname = []
    length = -1

    # loop until 0x00 byte encountered
    name_ptr = ptr
    while length != 0:
        # read length of label from bytes
        length = int.from_bytes(packet[name_ptr : name_ptr + 1], byteorder='big')
        name_ptr += 1
        ptr += 1

        # check if next length byte is a pointer for compression
        if length & 0xc0 != 0:
            # length byte is a pointer
            # read from pointer location instead
            name_ptr = int.from_bytes(packet[name_ptr - 1 : name_ptr + 1], byteorder='big')
            name_ptr = name_ptr & 0x3fff
            length = int.from_bytes(packet[name_ptr : name_ptr + 1], byteorder='big')
            name_ptr += 1
            hostname.append(packet[name_ptr : name_ptr + length].decode())

            # skip over second pointer byte
            name_ptr += length
            ptr += 1
        elif length > 0:
            # length byte isn't a pointer
            # read label and move base pointer
            hostname.append(packet[name_ptr : name_ptr + length].decode())

            # move base pointer
            name_ptr += length
            ptr += length

    # create original hostname from query
    return '.'.join(hostname), ptr

def parse_questions(packet, qdcount):
    questions = []

    # skip header
    bp = 12
    for _ in range(qdcount):
        # parse hostname
        hostname, bp = parse_hostnames(packet, bp)

        # parse qtype
        qtype = int.from_bytes(packet[bp:bp+2], byteorder='big')
        bp += 2

        # parse qclass
        qclass = int.from_bytes(packet[bp:bp+2], byteorder='big')
        bp += 2

        # append to questions
        questions.append(dict(hostname=hostname, qtype=qtype, qclass=qclass))

    return questions, bp

def parse_records(packet, count, bp):
    answers = []
    for _ in range(count):
        # parse qname
        # hostname is a pointer to question
        name = int.from_bytes(packet[bp:bp+2], byteorder='big')
        bp += 2

        # remove first 4 bits to get actual pointer value to hostname
        nameptr = name & 0x0fff

        # parse hostnames
        hostname, _ = parse_hostnames(packet, nameptr)

        # read record type
        typeof = int.from_bytes(packet[bp:bp+2], byteorder='big')
        bp += 2
        if typeof == 1:
            typeof = 'A'
        elif typeof == 5:
            typeof = 'CNAME'
        elif typeof == 2:
            typeof = 'NS'
        else:
            typeof = 'UNK'

        # read class of packet
        classof = int.from_bytes(packet[bp:bp+2], byteorder='big')
        bp += 2

        # read TTL 
        ttl = int.from_bytes(packet[bp:bp+4], byteorder='big')
        bp += 4

        # read length of address
        addr_length = int.from_bytes(packet[bp:bp+2], byteorder='big')
        bp += 2

        if typeof == 'A':
            # if A record, response is IP
            ip = []
            for i in range(addr_length):
                ip.append(str(int.from_bytes(packet[bp+i:bp+i+1], byteorder='big')))
            addr = '.'.join(ip)
        elif typeof == 'NS':
            # if NS record, response is hostname
            addr, _ = parse_hostnames(packet, bp)
        else:
            addr = None

        # move base pointer beyond address
        bp += addr_length

        # only care about NS and A records
        if typeof == 'UNK':
            continue

        # append to answers
        answers.append(dict(hostname=hostname, class_=classof, type=typeof, ttl=ttl, addr=addr))

    return answers, bp