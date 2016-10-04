import Network
import argparse
from time import sleep
import hashlib


class Packet:
    length_field_length = 10
    checksum_field_length = 32
    
    def __init__(self, seq_num, msg, flags=None):
        self.seq_num = seq_num
        self.msg = msg
        self.flags = flags

    def to_bytes(self):
        args = {
            'seq_num': self.seq_num,
            'flags': self.flags,
            'msg': self.msg
        }
        body = repr(args)
        checksum = Packet.calculate_checksum(body)
        length = str(self.length_field_length + self.checksum_field_length + len(body)).zfill(self.length_field_length)
        return length + checksum + body

    def calculate_checksum(body):
        return hashlib.md5(body.encode('utf-8')).hexdigest()
    
    def from_bytes(str_repr):
        print("Making packet from: {}".format(str_repr))
        str_repr = str_repr[Packet.length_field_length:]

        given_checksum = str_repr[:Packet.checksum_field_length]
        str_repr = str_repr[Packet.checksum_field_length:]

        calculated_checksum = Packet.calculate_checksum(str_repr)

        if given_checksum != calculated_checksum:
            return False

        args = eval(str_repr)
        pkt = Packet(args['seq_num'], args['msg'], args['flags'])

        return pkt

class RDT:
    ## latest sequence number used in a packet
    send_seq_num = 0
    rcv_seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = '' 
    received_packets = []

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

    def receive_packet(self):
        print("Receiving Packet... {}".format(self.received_packets))
        if len(self.received_packets) > 0:
            return self.received_packets.pop(0)
        return self.next_packet()

    def extract_packet(self):
        if len(self.byte_buffer) < Packet.length_field_length:
            return None

        length = int(self.byte_buffer[:Packet.length_field_length])
        if len(self.byte_buffer) < length:
            return None
        
        pkt = Packet.from_bytes(self.byte_buffer[:length])
        self.byte_buffer = self.byte_buffer[length:]

        return pkt
            
    def rdt_2_1_send(self, msg):
        print("Sending: {}".format(msg))
        pkt_to_send = Packet(self.send_seq_num, msg)
        self.network.udt_send(pkt_to_send.to_bytes())

        while True:
            pkt_rcv = self.next_packet()

            if pkt_rcv:
                if pkt_rcv.flags == 'ACK':
                    break
                
                self.network.udt_send(pkt_to_send.to_bytes())
                
                if pkt_rcv.flags is None:
                    self.received_packets.append(pkt_rcv)
            else:
                self.network.udt_send(pkt_to_send.to_bytes())
            
        self.send_seq_num = (self.send_seq_num + 1) % 2
        print("Finished sending: {}".format(msg))
        
    def rdt_2_1_receive(self):
        print("Receiving pkt")
        pkt_received = self.receive_packet()

        while not pkt_received:
            nak_pkt = Packet(None, None, 'NAK')
            self.network.udt_send(nak_pkt.to_bytes())
            
            print("Sent NAK, receiving next pkt")
            
            pkt_received = self.receive_packet()            

        print("Received pkt: {}".format(pkt_received))            
        ack_pkt = Packet(None, None, 'ACK')
        self.network.udt_send(ack_pkt.to_bytes())

        return pkt_received.msg
    
    def rdt_3_0_send(self, msg_S):
        pass
        
    def rdt_3_0_receive(self):
        pass
        

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
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()
        
        
    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
        


        
        
