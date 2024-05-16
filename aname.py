TYPE_A=1
TYPE_NS=2
TYPE_MD=3
TYPE_MF=4
TYPE_CNAME=5
TYPE_SOA=6
TYPE_MB=7
TYPE_MG=8
TYPE_MR=9
TYPE_NULL=10
TYPE_WKS=11
TYPE_PTR=12
TYPE_HINFO=13
TYPE_MINFO=14
TYPE_MX=15
TYPE_TXT=16
TYPE_AAAA=28
TYPE_AXFR=252
TYPE_ANY=255

CLASS_IN=1

def fqdn_from_name(name):
    ret=bytearray()
    for t in name.split('.'):
        b=t.encode('utf-8')
        n=len(b)
        if n>255:
            raise ValueError('Bad name')
        ret.append(n)
        ret.extend(b)
    ret.append(0)
    return ret

def fqdn_to_name(fqdn):
    ret=''
    n=len(fqdn)
    p=0
    while p<n:
        s, p=_cstr_get(fqdn, p)
        if ret:
            ret+='.'
        ret+=s
    return ret

def _cstr_get(b, p):
    q=b[p]
    p+=1
    q+=p
    return str(b[p:q], 'utf-8'), q
    
def _fqdn_get(b, p):
    r=bytearray()
    q=0
    while t:=b[p]:
        if t>=0xC0:
            if not q:
                q=p+2
            p=((t&0x3F)<<8)+b[p+1]
        else:
            r.extend(b[p:p+1+t])
            p=p+1+t
    return r, q or p+1

def _ans_get(b, p):
    fqdn, p=_fqdn_get(b, p)
    type=int.from_bytes(b[p:p+2], 'big')
    p+=2
    cls=int.from_bytes(b[p:p+2], 'big')
    p+=2
    ttl=int.from_bytes(b[p:p+4], 'big')
    p+=4
    length=int.from_bytes(b[p:p+2], 'big')
    p+=2
    data=None
    if type==TYPE_A:
        if length!=4:
            raise ValueError('Bad A record')
        data='{}.{}.{}.{}'.format(b[p], b[p+1], b[p+2], b[p+3])
    elif type==TYPE_NS or type==TYPE_CNAME or type==TYPE_PTR or \
         type==TYPE_MB or type==TYPE_MD or type==TYPE_MF or \
         type==TYPE_MG or type==TYPE_MR :
        data=fqdn_to_name(_fqdn_get(b, p)[0])
    elif type==TYPE_SOA:
        mname, q=_fqdn_get(b, p)
        rname, q=_fqdn_get(b, q)
        serial=int.from_bytes(b[q:q+4], 'big')
        q+=4
        refresh=int.from_bytes(b[q:q+4], 'big')
        q+=4
        retry=int.from_bytes(b[q:q+4], 'big')
        q+=4
        expire=int.from_bytes(b[q:q+4], 'big')
        q+=4
        ttl=int.from_bytes(b[q:q+4], 'big')
        data=(fqdn_to_name(mname), fqdn_to_name(rname), serial, refresh, retry, expire, ttl)
    elif type==TYPE_WKS:
        if length<5:
            raise ValueError('Bad WKS record')
        addr='{}.{}.{}.{}'.format(b[p], b[p+1], b[p+2], b[p+3])
        protocol=b[p+4]
        data=(addr, protocol, bytes(b[p+5:p+length]))
    elif type==TYPE_HINFO:
        cpu, q=_cstr_get(b, p)
        os=_cstr_get(b, q)[0]
        data=(cpu, os)
    elif type==TYPE_MINFO:
        rmail, q=_fqdn_get(b, p)
        email=_fqdn_get(b, q)[0]
        data=(fqdn_to_name(rmail), fqdn_to_name(email))
    elif type==TYPE_MX:
        reference=int.from_bytes(b[p:p+2], 'big')       
        data=(reference, fqdn_to_name(_fqdn_get(b, p+2)[0]))
    elif type==TYPE_TXT:
        data=[]
        q=p
        r=p+length
        while q<r:
            s, q=_cstr_get(b, q)
            data.append(s)
    elif type==TYPE_AAAA:
        if length!=16:
            raise ValueError('Bad AAAA record')
        data='{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}'.format(
            *(int.from_bytes(b[p+t:p+t+2], 'big') for t in range(0,16,2))
            )
    else:
        data=bytes(b[p:p+length])
    p+=length
    return (fqdn_to_name(fqdn), type, cls, ttl, data), p

def nsclient():
    import socket
    client=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(('0.0.0.0', 0))        
    client.settimeout(0)
    return client

# server must be in dot-number format like '8.8.8.8'
# return (answer:[resp1, resp2, ...], authority:[resp...], additional:[resp:...])
# response is (name, type, class, ttl, data) 
async def nslookup(name, server, type=TYPE_A, cls=CLASS_IN, client=None, timeout=2, retries=3):
    from asyncio import sleep_ms
    if not client:
        client=nsclient()
    # make request
    req=bytearray()
    req.extend(__import__('os').urandom(2)) # 2 random bytes
    req.extend(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    req.extend(fqdn_from_name(name))
    req.extend(type.to_bytes(2, 'big'))
    req.extend(cls.to_bytes(2, 'big'))
    # send and wait response
    t=0
    timeout*=1000
    while True:
        # do not catch send error (maybe EHOSTUNREACH if network is not connected)
        if t==0:
            client.sendto(req, (server, 53))        
        try:
            # maybe it's the best way for UDP transmission that does not require high response speed
            await sleep_ms(300)
            t+=300
            resp=client.recv(1024)
            if len(resp)>12 and resp[0]==req[0] and resp[1]==req[1] \
               and resp[2]&0x80 and resp[3]&0x0f==0:
                break
        except OSError as e:
            pass
        if t>timeout:
            t=0
            retries-=1
            if retries<0:
                raise OSError(-202) # same behavior like socket.getaddrinfo()
    # parse response
    resp=memoryview(resp)
    qcnt=int.from_bytes(resp[4:6], 'big')
    ancnt=int.from_bytes(resp[6:8], 'big')
    aucnt=int.from_bytes(resp[8:10], 'big')
    adcnt=int.from_bytes(resp[10:12], 'big')
    pos=12
    # skip question
    for t in range(qcnt):
        pos=_fqdn_get(resp, pos)[1]
        pos+=4 # type and cls
    # no distinction between answer, authority, additional RPs
    ret=([],[],[])
    for t in range(ancnt):
        ans, pos=_ans_get(resp, pos)
        ret[0].append(ans)
    for t in range(aucnt):
        ans, pos=_ans_get(resp, pos)
        ret[1].append(ans)
    for t in range(adcnt):
        ans, pos=_ans_get(resp, pos)
        ret[2].append(ans)
    return ret


# return list of (family, type, proto, canonname, sockaddr) like socket.getaddrinfo()
async def getaddrinfo(host, port, af=0, type=0, proto=0, flags=0, *, server=None, client=None):
    from socket import AF_INET
    if af and af!=AF_INET:
        raise OSError(-202)
    host=host.strip()
    if all(t.isdigit() for t in host.split('.')):
        return [(AF_INET, type, proto, host, (host, port)), ]
    if not client:
        client=nsclient()
    if not server:
        import network
        sta=network.WLAN(network.STA_IF)
        if not sta.active() or sta.status()!=network.STAT_GOT_IP:
            raise OSError(113)
        server=sta.ifconfig()[3]
    rec_a=[]
    rec_cname=[]
    for ans in await nslookup(host, server=server, client=client):
        for rec in ans:
            if rec[1]==TYPE_A:
                rec_a.append((rec[0], rec[4]))
            elif rec[1]==TYPE_CNAME and rec[0]==host:
                rec_cname.append(rec[4])
    ret=[]
    for a in rec_a:
        if a[0]==host or a[0] in rec_cname:
            ret.append((AF_INET, type, proto, host, (a[1], port)))
    # not do recursive lookup by myself
    if not ret:
        raise OSError(-202)

    return ret
