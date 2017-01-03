# Code base for simple traceroute
#
# To run:
#
#   sudo python3 icmp_traceroute.py
#



#Justin Kim COMP360

import socket
import struct
import sys
import time

class IcmpTraceroute():

    def __init__(self, src_ip, dst_ip, ip_id, ip_ttl, icmp_id, icmp_seqno):

        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ip_id = ip_id
        self.max_ttl = ip_ttl
        self.ip_ttl = 1
        self.icmp_id = icmp_id
        self.icmp_seqno = icmp_seqno
        print('ICMP traceroute created')

    def run_traceroute(self):

        # Iterate as many times as TTL values
        for ttl in range (2, self.max_ttl + 1):

            # Create ICMP pkt, process response and compute statistics
            (dst_address,startTime,EndTime) = self.traceroute()

            # Print statistics for this run            
            RTT = EndTime - startTime #Computer RTT (Time starts when the ICMP packet is sent and ends when reply is recieved)
            print ('[     TTL     ]       [Destination IP Address]       [     RTT     ]')
            print ('      [%i]                [%s]                [%f]' %(self.ip_ttl,dst_address,RTT))

            # Update variables for next run
            self.ip_id = self.ip_id + 1
            self.icmp_id = self.ip_id + 1
            self.ip_ttl = ttl

    def traceroute(self):

        # Create packet
        ip_header = self.create_ip_header()
        icmp_header = self.create_icmp_header()
        bin_echo_req = ip_header + icmp_header
        # Create send and receive sockets
        send_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Set IP_HDRINCL flag so kernel does not rewrite header fields
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        start = time.time()

        # Set receive socket timeout to 2 seconds
        recv_sock.settimeout(2.0)

        # Send packet to destination
        try:
            send_sock.sendto(bin_echo_req, (self.dst_ip, 0))
            end = time.time()
        except OSError as e:
            print('Unable to send packet, exiting')
            exit(0)

        # Receive echo reply (hopefully)
        try:
            [bin_echo_reply, addr] = recv_sock.recvfrom(1024)
        except (socket.timeout, OSError) as e:
            print('No response, exiting')
            exit(0)

        # Extract info from ip_header
        [ip_header_length, ip_identification, ip_protocol,
                ip_src_addr]  = self.decode_ip_header(bin_echo_reply)

        # Extract info from icmp_header
        [icmp_type, icmp_code] = self.decode_icmp_header(
                bin_echo_reply, ip_header_length)

        return(ip_src_addr,start,end)

    def create_ip_header(self):

        # Returned IP header is packed binary data in network order
        ip_version= 4 #Always going to be 4 because IPv4
        ip_header_length= 5 #since in multiples of 32 (5*32bits = 5*4bytes = 20 Bytes)
        ip_tos= 0 #Routine TOS. No Priority
        ip_totallength= 0
        ip_identification= self.ip_id #IP_ID that was initialized
        ip_flags= 2 # Do not fragment=
        ip_fragoffset= 0 #No Fragoffset because no fragmentation
        ip_ttl= self.ip_ttl 
        ip_protocol= 1 #1 is the protocol number for ICMP
        ip_checksum=0 
        try:
            #Convert addresses into 32-bit packed binary format
            ip_src_addr= socket.inet_aton(self.src_ip) 
            ip_dst_addr= socket.inet_aton(self.dst_ip)
        except OSError as e:
            print("INVALID DST/SRC ADDRESS",e)

        ip_header= struct.pack('!BBHHHBBH4s4s', 
        self.connectBits(ip_version,ip_header_length,4), #Total (IPVersion(4) + IPHeaderLength(4) = 8 bits)
        ip_tos, #8 Bits
        ip_totallength, #16 bits
        ip_identification,#16 bits
        self.connectBits(ip_flags,ip_fragoffset,13),#Total (ip_flags(3)+ip_fragoffset(13) = 16 bits)
        ip_ttl,#8 Bits
        ip_protocol,#8 Bits
        ip_checksum,#16 bits
        ip_src_addr,#4 8 bit characters for a total of 32 bits
        ip_dst_addr)#4 8 bit characters for a total of 32 bits
        

        return ip_header

    def connectBits(self,f1,f2,s2): 
        #Concatenates the bits into the appropriate size
        return (f1*(2**s2))+f2


    def create_icmp_header(self):

        ECHO_REQUEST_TYPE = 8
        ECHO_CODE = 0

        # ICMP header info from https://tools.ietf1.org/html/rfc792
        icmp_type = ECHO_REQUEST_TYPE      # 8 bits
        icmp_code = ECHO_CODE              # 8 bits
        icmp_checksum = 0                  # 16 bits
        icmp_identification = self.icmp_id # 16 bits
        icmp_seq_number = self.icmp_seqno  # 16 bits

        # ICMP header is packed binary data in network order
        icmp_header = struct.pack('!BBHHH', # ! means network order
        icmp_type,           # B = unsigned char = 8 bits
        icmp_code,           # B = unsigned char = 8 bits
        icmp_checksum,       # H = unsigned short = 16 bits
        icmp_identification, # H = unsigned short = 16 bits
        icmp_seq_number)     # H = unsigned short = 16 bits

        return icmp_header


    def decode_ip_header(self, bin_echo_reply):

        # Decode ip_header
        ip_header = bin_echo_reply[:20]
        unpackedIpHead = struct.unpack('!BBHHHBBH4s4s',ip_header)
        # Extract fields of interest
        ip_header_length = (unpackedIpHead[0] - 64)*4 #Separate the Version from the header length
        ip_identification = unpackedIpHead[3] 
        ip_protocol = unpackedIpHead[6] 
        ip_src_addr = socket.inet_ntoa(unpackedIpHead[8])
        return [ip_header_length, ip_identification,
                ip_protocol, ip_src_addr]

    def decode_icmp_header(self, bin_echo_reply, ip_header_length):
 
        # Note: Echo Reply contains entire IP packet that triggered
        # it. Enables Echo Reply to be matched with originating
        # Echo Request. You are not required to decode this
        # payload, simply the ICMP header of the Echo Reply

        # Decode icmp_header
        icmp_header = bin_echo_reply[ip_header_length:ip_header_length+8]
        unpackedICMPhead = struct.unpack('!BBHHH',icmp_header)
        # Extract fields of interest
        icmp_type = icmp_header[0] # Should equal 11, for Time-to-live exceeded
        icmp_code = icmp_header[1] # Should equal 0

        return [icmp_type, icmp_code]


def main():
    src_ip = '192.168.1.12' # Your IP addr (e.g., IP address of VM)
    dst_ip = '130.81.216.40' # IP addr behind Wesleyan firewall
    ip_id = 111             # IP header in wireshark should have
    ip_ttl = 2            # 1 or 2 if you're on Wesleyan network
    icmp_id = 222           
    icmp_seqno = 1          # Starts at 1, by convention

    if len(sys.argv) > 1:
        src_ip = sys.argv[1]
        dst_ip = sys.argv[2]
        ip_id = int(sys.argv[3])
        ip_ttl = int(sys.argv[4])
        icmp_id = int(sys.argv[5])
        icmp_seqno = int(sys.argv[6])
    

    traceroute = IcmpTraceroute(
            src_ip, dst_ip, ip_id, ip_ttl, icmp_id, icmp_seqno)
    traceroute.run_traceroute()

if __name__ == '__main__':
    main()
