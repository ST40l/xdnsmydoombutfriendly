import socket
import struct
import select
import time

TYPE_MX = 15
CLASS_IN = 1

def mx_alloc(n):
    return bytearray(n)

def mx_free(p):
    pass

def mx_dns2qname(domain):
    buf = bytearray()
    labels = domain.split('.')
    for label in labels:
        buf.append(len(label))
        buf.extend(label.encode())
    buf.append(0)
    return buf

def mx_make_query(sock, dns_addr, domain, req_flags):
    buf = mx_alloc(1024)
    i = 0
    buf[i:i+2] = struct.pack('H', 1234)  # Use any random ID for the DNS query
    i += 2
    buf[i:i+2] = struct.pack('H', req_flags)
    i += 2
    buf[i:i+2] = struct.pack('H', 0x0001)  # qncount
    i += 2
    buf[i:i+2] = struct.pack('H', 0)  # ancount
    i += 2
    buf[i:i+2] = struct.pack('H', 0)  # nscount
    i += 2
    buf[i:i+2] = struct.pack('H', 0)  # arcount

    qname_buf = mx_dns2qname(domain)
    buf[i:i+len(qname_buf)] = qname_buf
    i += len(qname_buf)

    buf[i:i+2] = struct.pack('H', TYPE_MX)  # type
    i += 2
    buf[i:i+2] = struct.pack('H', CLASS_IN)  # class
    i += 2

    tmp = sock.sendto(buf[:i], dns_addr)
    return 1 if tmp <= 0 else 0

def mx_decode_domain(buf, pos, len):
    out = bytearray()
    retpos, sw = 0, 0

    while pos < len:
        n = buf[pos]
        if n == 0:
            pos += 1
            break
        elif n < 64:
            pos += 1
            out.extend(buf[pos:pos+n])
            out.append(ord('.'))
            pos += n
        else:
            if sw == 0:
                retpos = pos + 2
            sw = 1
            n = struct.unpack('H', buf[pos:pos+2])[0] & 0x3FFF
            pos = n
            if pos >= len:
                break

    return pos if sw == 0 else retpos, out[:-1].decode()

def mx_parse_rr(buf, reply_len):
    root, top = None, None
    reply_hdr = struct.unpack('!HHHHHH', buf[:12])

    if reply_len < 12:
        return None

    i, rr_count = 12, reply_hdr[1] + reply_hdr[2] + reply_hdr[3]
    i, _ = mx_skipqn(buf, i, reply_len, reply_hdr)

    if i >= reply_len:
        return None

    for rr in range(rr_count):
        tmp_rr = {}
        i, tmp_rr['domain'] = mx_decode_domain(buf, i, reply_len)
        if (i + 10) >= reply_len:
            break
        tmp_rr['rr_type'] = struct.unpack('!H', buf[i:i+2])[0]
        i += 2
        tmp_rr['rr_class'] = struct.unpack('!H', buf[i:i+2])[0]
        i += 2
        i += 4  # 32-bit TTL
        tmp_rr['rdlen'] = struct.unpack('!H', buf[i:i+2])[0]
        i += 2
        tmp_rr['rdata_offs'] = i
        if tmp_rr['rdlen'] < 0 or (i + tmp_rr['rdlen']) > reply_len:
            break

        newrr = mx_alloc(16)
        newrr[0:2] = struct.pack('!H', tmp_rr['rr_type'])
        newrr[2:4] = struct.pack('!H', tmp_rr['rr_class'])
        newrr[4:8] = b'\x00\x00\x00\x00'  # 32-bit TTL
        newrr[8:10] = struct.pack('!H', tmp_rr['rdlen'])
        newrr[10:16] = buf[tmp_rr['rdata_offs']:tmp_rr['rdata_offs'] + 6 + tmp_rr['rdlen']]

        newrr_ptr = struct.unpack('P', newrr)[0]

        if top is None:
            root = top = newrr_ptr
        else:
            top[0:8] = struct.pack('!Q', newrr_ptr)
            top = newrr_ptr

    return root

def my_get_mx_list2(dns_addr, domain):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    buf_size = 4096
    buf = bytearray(buf_size)

    try:
        for loc_retry in range(2):
            mxlist_root = None

            if loc_retry == 0:
                query_fl = 0x0100
            else:
                query_fl = 0

            if mx_make_query(sock, dns_addr, domain, query_fl):
                continue

            ready, _, _ = select.select([sock], [], [], 12)
            if not ready:
                continue

            reply_len, _ = sock.recvfrom_into(buf)
            if reply_len <= 0 or reply_len <= 12:
                continue

            reply_hdr = struct.unpack('!HHHHHH', buf[:12])
            rrcode = reply_hdr[1] & 0x0F

            if rrcode == 3:
                return None, 2
            if (rrcode == 2) and (reply_hdr[1] & 0x80):
                return None, 2
            if rrcode != 0:
                continue

            rrlist = mx_parse_rr(buf, reply_len)
            if rrlist is None:
                continue

            mxlist_root = mxlist_top = None
            while rrlist:
                rr = struct.unpack('!Q', rrlist[:8])[0]
                mxlist_new = {}
                mxlist_new['pref'] = struct.unpack('!H', rr[:2])[0]
                _, mxlist_new['mx'] = mx_decode_domain(rr, 2, len(rr))

                if mxlist_new['mx'] == '':
                    continue

                if mxlist_top is None:
                    mxlist_root = mxlist_top = mxlist_new
                else:
                    mxlist_top['next'] = mxlist_new
                    mxlist_top = mxlist_new

                rrlist = rrlist[8:]

            if mxlist_root is None:
                continue

            return mxlist_root, 1

    finally:
        sock.close()

    return None, 1

def my_get_mx_list(dns_addr, domain):
    for _ in range(2):
        mx_list, e = my_get_mx_list2(dns_addr, domain)
        if mx_list is not None:
            return mx_list
        if e == 2:
            break
        time.sleep(0.1)
    return None

def get_mx_list(domain, dns_server):
    dns_addr = (dns_server, 53)
    mx_list = my_get_mx_list(dns_addr, domain)
    return mx_list

def free_mx_list(p):
    pass

def main():
    domain = input("Enter the domain name: ")
    dns_server = input("Enter the DNS server address (e.g., 8.8.8.8): ")
    mx_list = get_mx_list(domain, dns_server)
    if mx_list:
        for mx in mx_list:
            print(f"Preference: {mx['pref']}, MX: {mx['mx']}")
    else:
        print("No MX records found.")

if __name__ == "__main__":
    main()
