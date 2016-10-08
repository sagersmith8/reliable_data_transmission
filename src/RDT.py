import Network
import argparse
from time import sleep, time
import hashlib

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32 
        
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
        
    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)
        
        
    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
   
    
    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        
        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S

class Packet_RDT_2_1:
    length_field_length = Packet.length_S_length
    checksum_field_length = 32
    pkt_no = 0
    
    def __init__(self, seq_num, msg, flags=None):
        Packet_RDT_2_1.pkt_no += 1
        
        self.seq_num = seq_num
        self.msg = msg
        self.flags = flags
        self.pkt_no = Packet_RDT_2_1.pkt_no

    def to_bytes(self):
        args = {
            'pkt_no': self.pkt_no,
            'seq_num': self.seq_num,
            'flags': self.flags,
            'msg': self.msg
        }
        body = repr(args)
        checksum = Packet_RDT_2_1.calculate_checksum(body)
        length = str(self.length_field_length + self.checksum_field_length + len(body)).zfill(self.length_field_length)
        return length + checksum + body

    def calculate_checksum(body):
        return hashlib.md5(body.encode('utf-8')).hexdigest()
    
    def from_bytes(str_repr):
        ##print("Making packet from: {}".format(str_repr))
        str_repr = str_repr[Packet_RDT_2_1.length_field_length:]

        given_checksum = str_repr[:Packet_RDT_2_1.checksum_field_length]
        str_repr = str_repr[Packet_RDT_2_1.checksum_field_length:]

        calculated_checksum = Packet_RDT_2_1.calculate_checksum(str_repr)

        if given_checksum != calculated_checksum:
            return False

        args = eval(str_repr)
        pkt = Packet_RDT_2_1(args['seq_num'], args['msg'], args['flags'])
        pkt.pkt_no = args['pkt_no']
        return pkt

    def __str__(self):
        return self.to_bytes()

class RDT:
    ## latest sequence number used in a packet
    send_seq_num = 0
    rcv_seq_num = 0

    seq_num = 0
    
    ## buffer of bytes read from network
    byte_buffer = '' 
    received_packets = []

    TIMEOUT = 1
    
    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
    
    def disconnect(self):
        self.network.disconnect()            

    def next_packet(self):
        pkt = self.extract_packet()
        while pkt is None:
            self.byte_buffer += self.network.udt_receive()
            pkt = self.extract_packet()
        return pkt

    def next_packet_timeout(self, deadline):
        pkt = self.extract_packet()
        while pkt is None and time() < deadline:
            self.byte_buffer += self.network.udt_receive()
            pkt = self.extract_packet()

        if pkt is None:
            return 'timeout'
        return pkt    

    def extract_packet(self):
        if len(self.byte_buffer) < Packet_RDT_2_1.length_field_length:
            return None

        length = int(self.byte_buffer[:Packet_RDT_2_1.length_field_length])
        if len(self.byte_buffer) < length:
            return None
        
        pkt = Packet_RDT_2_1.from_bytes(self.byte_buffer[:length])
        self.byte_buffer = self.byte_buffer[length:]

        return pkt
            
    def rdt_2_1_send(self, msg):
        #print("Trying to SEND {}: {}".format(self.send_seq_num, msg))

        pkt_to_send = Packet_RDT_2_1(self.send_seq_num, msg)
        #print("Sent pkt: {}".format(pkt_to_send))        
        self.network.udt_send(pkt_to_send.to_bytes())
        
        while True:
            pkt_rcv = self.next_packet()
            #print("Got pkt: {}".format(pkt_rcv))
            
            if pkt_rcv:
                ##print("{} Received: {}".format(time(), pkt_rcv.to_bytes()))
                if pkt_rcv.flags == 'ACK {}'.format(pkt_to_send.seq_num):
                    break

                if pkt_rcv.flags is None:
                    if pkt_rcv.seq_num != self.rcv_seq_num:
                        ##print("{} While sending, wrong sequence number, sending ACK...".format(time()))
                        ack_pkt = Packet_RDT_2_1(None, None, 'ACK {}'.format(pkt_rcv.seq_num))
                        #print("Sent pkt: {}".format(ack_pkt))
                        self.network.udt_send(ack_pkt.to_bytes())
                        
                #print("Resent pkt: {}".format(pkt_to_send))
                self.network.udt_send(pkt_to_send.to_bytes())                    
            else:
                #print("Resent pkt: {}".format(pkt_to_send))
                self.network.udt_send(pkt_to_send.to_bytes())
            
        self.send_seq_num = (self.send_seq_num + 1) % 2
        ##print("{} Finished sending: {}".format(time(), msg))
        
    def rdt_2_1_receive(self):
        #print("Trying to RECEIVE {}".format(self.rcv_seq_num))
        while True:
            pkt_received = self.next_packet()
            #print("Got pkt: {}".format(pkt_received))

            if not pkt_received:
                ##print("{} Corrupt packet, sending NAK...".format(time()))
                nak_pkt = Packet_RDT_2_1(None, None, 'NAK {}'.format(self.rcv_seq_num))
                #print("Sent pkt: {}".format(nak_pkt))
                self.network.udt_send(nak_pkt.to_bytes())
                continue

            if pkt_received.flags is not None:
                continue
            
            if pkt_received.seq_num != self.rcv_seq_num:
                ##print("{} Wrong sequence number, sending ACK...".format(time()))
                ack_pkt = Packet_RDT_2_1(None, None, 'ACK {}'.format(pkt_received.seq_num))
                #print("Sent pkt: {}".format(ack_pkt))
                self.network.udt_send(ack_pkt.to_bytes())
                continue

            break

        ack_pkt = Packet_RDT_2_1(None, None, 'ACK {}'.format(pkt_received.seq_num))
        #print("Sent pkt: {}".format(ack_pkt))                        
        self.network.udt_send(ack_pkt.to_bytes())

        self.rcv_seq_num = (self.rcv_seq_num + 1) % 2
        return pkt_received.msg
    
    def rdt_3_0_send(self, msg):
        #print("Trying to SEND {}: {}".format(self.send_seq_num, msg))

        pkt_to_send = Packet_RDT_2_1(self.send_seq_num, msg)
        #print("Sent pkt: {}".format(pkt_to_send))        
        self.network.udt_send(pkt_to_send.to_bytes())
        deadline = time() + RDT.TIMEOUT
        
        while True:
            pkt_rcv = self.next_packet_timeout(deadline)
            #print("Got pkt: {}".format(pkt_rcv))

            if pkt_rcv == 'timeout':
                #print("Resent pkt: {}".format(pkt_to_send))
                self.network.udt_send(pkt_to_send.to_bytes())
                deadline = time() + RDT.TIMEOUT                
            elif pkt_rcv:
                ##print("{} Received: {}".format(time(), pkt_rcv.to_bytes()))
                if pkt_rcv.flags == 'ACK {}'.format(pkt_to_send.seq_num):
                    break

                if pkt_rcv.flags is None:
                    if pkt_rcv.seq_num != self.rcv_seq_num:
                        ##print("{} While sending, wrong sequence number, sending ACK...".format(time()))
                        ack_pkt = Packet_RDT_2_1(None, None, 'ACK {}'.format(pkt_rcv.seq_num))
                        #print("Sent pkt: {}".format(ack_pkt))
                        self.network.udt_send(ack_pkt.to_bytes())
                        
                #print("Resent pkt: {}".format(pkt_to_send))
                self.network.udt_send(pkt_to_send.to_bytes())
                deadline = time() + RDT.TIMEOUT                
            else:
                #print("Resent pkt: {}".format(pkt_to_send))
                self.network.udt_send(pkt_to_send.to_bytes())
                deadline = time() + RDT.TIMEOUT                
            
        self.send_seq_num = (self.send_seq_num + 1) % 2
        
    def rdt_3_0_receive(self):
        #print("Trying to RECEIVE {}".format(self.rcv_seq_num))
        while True:
            pkt_received = self.next_packet()
            #print("Got pkt: {}".format(pkt_received))

            if not pkt_received:
                continue

            if pkt_received.flags is not None:
                continue
            
            if pkt_received.seq_num != self.rcv_seq_num:
                ##print("{} Wrong sequence number, sending ACK...".format(time()))
                ack_pkt = Packet_RDT_2_1(None, None, 'ACK {}'.format(pkt_received.seq_num))
                #print("Sent pkt: {}".format(ack_pkt))
                self.network.udt_send(ack_pkt.to_bytes())
                continue

            break

        ack_pkt = Packet_RDT_2_1(None, None, 'ACK {}'.format(pkt_received.seq_num))
        #print("Sent pkt: {}".format(ack_pkt))                        
        self.network.udt_send(ack_pkt.to_bytes())

        self.rcv_seq_num = (self.rcv_seq_num + 1) % 2      
        return pkt_received.msg

    def rdt_1_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        self.seq_num += 1
        self.network.udt_send(p.get_byte_S())
        
    def rdt_1_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            #check if we have received enough bytes
            if(len(self.byte_buffer) < Packet.length_S_length):
                return ret_S #not enough bytes to read packet length
            #extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S #not enough bytes to read the whole packet
            #create packet from buffer content and add to return string
            p = Packet.from_byte_S(self.byte_buffer[0:length])
            ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            #remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            #if this was the last packet, will return on the next iteration

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        ##print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        ##print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
