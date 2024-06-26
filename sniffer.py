import time
from socket import AF_PACKET, SOCK_RAW, SO_RCVBUF, SOL_SOCKET, ntohs, inet_ntoa, socket
import netifaces as ni
import logging
import struct
from ctypes import *
import argparse

import threading
import queue


logger = logging.getLogger('sniffer')
logging.basicConfig(format='%(asctime)s %(message)s', filename='/var/log/sniffer.log', encoding='utf-8', level=logging.DEBUG)



#class that represents the TCP header and maps raw bytes (from socket) to the corresponding TCP header fields
class TCP(Structure):

    _fields_ = [

        ("src",           c_ushort),
        ("dst",           c_ushort),
        ("seq",           c_uint),
        ("ack",           c_uint),
        ("hlen_res_flags",c_short),
        #("hdr_len",       c_ubyte, 4),
        #("reserved",      c_ubyte, 6),
        #("flags",         c_ubyte, 6),
        ("window_size",   c_ushort),
        ("checksum",      c_ushort),
        ("urgent",        c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)    
        
    def __init__(self, socket_buffer=None):

        self.src_port = struct.unpack("!H", (struct.pack("<H", self.src)))[0]
        self.dst_port = struct.unpack("!H", (struct.pack("<H", self.dst)))[0]


        self.hlen_res_flags_reversed = struct.unpack("!H", (struct.pack("<H", self.dst)))[0]

        #SYN enabled is 0x0002  -> without reversing byte order it becomes 0x0200

        #mask the last 6 bits to get the enabled flags
        self.flags = self.hlen_res_flags & 0x3F00

        
        #only SYN must be enabled. 512 is the equivalent of 0x0200 (SYN enabled) 
        self.syn = self.flags == 512




#class that represents the IP header
class IP(Structure):
    
    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte),
        ("len",           c_ushort),
        ("id",            c_ushort),
        ("offset",        c_ushort),
        ("ttl",           c_ubyte),
        ("protocol_num",  c_ubyte),
        ("checksum",      c_ushort),
        ("src",           c_uint),
        ("dst",           c_uint)
    ]
    
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)    
        
    def __init__(self, socket_buffer=None):

        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        
        
        # human readable IP addresses
        self.src_address = inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = inet_ntoa(struct.pack("<L",self.dst))

    
        # human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

        self.header_len = self.ihl * 4
        self.ip_version = self.version
           


#potential scanners and the volume of traffic they generate has to be tracked;
#Each potential scanner has a list of scanned ports. An alert is generated if the src_ip scans more than
#SYN_THRESHOLD ports within the time window
class Scanner:
    
        def __init__(self, ip:str):
    
            self.ip = ip
            self.ports = []
            self.syn_counter = 0

            self.SYN_THRESHOLD = 30 

            #timestamp of the first SYN packet
            self.window_start_timestamp = time.time()

            #time window of 30 seconds
            self.window_len = 40
            self.window_end_timestamp = self.window_start_timestamp + self.window_len


            self.downtime_end = -1


        def is_in_downtime(self):
            if(self.downtime_end == -1):
                return False
            return (time.time() - self.downtime_end) <= 0
    
        def add_port(self, port:int):
    
            if(self.is_in_downtime() is False and self.downtime_end == -1):
                self.downtime_end = -1

            self.ports.append(port)
            self.syn_counter += 1


            #self.window_end_timestamp += self.get_remaining_time() * 0.5
            self.window_end_timestamp += self.window_len * 0.5
            
            print(self.window_end_timestamp)
    
        def get_ports(self):
            return self.ports
    
        def get_ip(self):
            return self.ip
    
        def get_port_counter(self):
            return self.syn_counter
        
        def get_window_start(self):
            return self.window_start_timestamp
        
        def get_window_end(self):
            return self.window_end_timestamp
        
        def get_remaining_syn(self):
            return self.SYN_THRESHOLD - self.syn_counter
        
        #a negative number means the window has expired
        def get_remaining_time(self):
            return self.window_end_timestamp - time.time()



#Sniff an interface and filter traffic
class Sniffer:

    def __init__(self, interface:str):

        self.interface = interface

        #get mac address
        tmp_addr = ni.ifaddresses(self.interface)[ni.AF_LINK][0]['addr']
        self.interface_mac_addr = [int(i, 16) for i in tmp_addr.split(':')]

        self.sniffer = None
        self.queue = queue.Queue()

        #start a 2nd thread to analyze filtered traffic
        self.analyzer = threading.Thread(target=self._analyze_packets).start()

        self.scanners_dict = {}


        


    #Method executed by a second thread that reads data from a blocking queue and keeps track of potential scanners
    def _analyze_packets(self):


        logger.debug('starting analyzer')

        #use these timers to remove useless entries from dictionaries every 10 minutes
        current_time = time.time()
        cleanup_time = current_time + 60
        

        while True:

 
            #update current_time
            current_time = time.time()


            if(current_time >= cleanup_time):
                self._cleanup_routine()
                current_time = time.time()
                cleanup_time = current_time + 60


            #(ip_src, src_port, dst_port)
            item = self.queue.get()

            if(item[0] == "exit"):
                break


            #source IP has already been mapped
            if(item[0] in self.scanners_dict):

                scanner = self.scanners_dict[item[0]]


                if(scanner.is_in_downtime()):
                    continue

                #time window expired, remove ip from dictionary
                if(scanner.get_remaining_time() < 0):
                    del(self.scanners_dict[item[0]])


                else:
                    dst_port = item[2]

                    #a new port has been scanned
                    if(dst_port not in scanner.get_ports()):

                        scanner.add_port(dst_port)

                        #did the 'attacker' scan more than THRESHOLD ports? If so alert
                        if(scanner.get_remaining_syn() <= 0):

                            self._alert(scanner.get_ip())


            #new ip_src has scanned a single port
            if(item[0] not in self.scanners_dict):

                print("new ip: " + item[0])

                #new IP address to monitor, create a new scanner object and add the port that it has just scanned
                self.scanners_dict[item[0]] = Scanner(item[0])
                self.scanners_dict[item[0]].add_port(item[2])

            
        logger.debug("analyzer exiting")
        self.queue.task_done()


    def _alert(self, ip_src):

        temp_string = "inbound scan by ip: " + ip_src
        logger.info(temp_string)

        print(temp_string)


        #5 minutes downtime
        self.scanners_dict[ip_src].downtime_end = time.time() + 80
        #self.scanners_dict[ip_src].window_end_timestamp = -1
        



    
    def _bind_interface(self):

        if(self.interface is not None):
            self.sniffer.bind((self.interface, 0))
            self.sniffer.setsockopt(SOL_SOCKET, SO_RCVBUF, 2**30)



    #Not all IP packets contain TCP segments
    def _filter_IP(self, ip_packet):

        ip_hdr = IP(ip_packet[0:20])

        if(ip_hdr.ip_version != 4):
            return (False, 0, -1)
        
        if(ip_hdr.protocol != "TCP"):
            return (False, 0, -1)



        payload_index = ip_hdr.header_len
        payload = ip_packet[payload_index:]

        return (True, payload, ip_hdr.src_address)
    

    #check for SYN packets
    def _filter_TCP(self, ip_payload):

        #tcp header (excluding options)
        tcp_hdr = TCP(ip_payload[0:20])
        
        if(tcp_hdr.src_port < 1024):
            return (False, -1, -1)

        if(tcp_hdr.syn is False):
            return (False, -1, -1)


        return (True, tcp_hdr.src_port, tcp_hdr.dst_port)


    def start(self):

        self.sniffer = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))

        self._bind_interface()

        logger.info('sniffer has started')

        try:
            while True:

                #capture frame
                raw_buffer = self.sniffer.recvfrom(65565)[0]

                if(len(raw_buffer) <= 0):
                    break


                #parse Ethernet header
                #! = network byte order
                #B = unsigned char (1 byte)
                #get the src mac address to void packets that are being sent by the monitored interface
                #H = unsigned short (2 bytes)
  

                eth_header = struct.unpack("!6sBBBBBBH", raw_buffer[0:14])

                
                #check the 3rd struct field (Ether type). When transporting IP packets it must be 0x800
                if(eth_header[7] != 0x800):
                    continue


                #check if the src mac address corresponds to that of the interface we are monitoring

                if(list(eth_header[1:7]) == self.interface_mac_addr):
                    #print("packet sent by the monitored interface")
                    continue

                

               

                is_ip_tcp, payload, ip_src = self._filter_IP(raw_buffer[14:])

                if(is_ip_tcp is False or payload == 0):
                    continue

                
                tcp_filter_res, src_port, dst_port = self._filter_TCP(payload)
                if(tcp_filter_res is False):
                    continue

                self.queue.put((ip_src, src_port, dst_port))


                

        # handle CTRL+C
        except KeyboardInterrupt:
            logger.info('main exiting')
            self.sniffer.close()
            self.queue.put(("exit", 0, 0))


    
    def _cleanup_routine(self):
        

        logger.debug('analyzer thread entering cleanup routine')
        dict_elems = len(self.scanners_dict)

        logger.debug('elems in dict: ' + str(dict_elems)) 


        print("elements in dict before clean up: " + str(len(self.scanners_dict))) 


        #first cleanup scanner dict
        self.scanners_dict = {k: v for k,v in self.scanners_dict.items() if (v.get_remaining_time() > 0 and v.is_in_downtime() is False)} 

        print("elements in dict after clean up: " + str(len(self.scanners_dict))) 

        logger.debug('elems in dict: ' + str(len(self.scanners_dict)))

        logger.debug('analyzer thread exiting cleanup routine')



if __name__ == '__main__':


    interface = "eth0"
    parser = argparse.ArgumentParser(description="detect port scans by monitoring an interface")
    parser.add_argument('-i', '--interface', type=str, help='specify interface to capture from')


    args = parser.parse_args()
    if(args.interface is not None):
        interface = args.interface

    sniffer = Sniffer(interface)
    sniffer.start()

