import asyncio
from bitstring import BitArray
import binascii
import hmac
import hashlib
import socket

# Known IPSC Message Types
CALL_CONFIRMATION     = b'\x05' # Confirmation FROM the recipient of a confirmed call.
TXT_MESSAGE_ACK       = b'\x54' # Doesn't seem to mean success, though. This code is sent success or failure
CALL_MON_STATUS       = b'\x61' #  |
CALL_MON_RPT          = b'\x62' #  | Exact meaning unknown
CALL_MON_NACK         = b'\x63' #  |
XCMP_XNL              = b'\x70' # XCMP/XNL control message
GROUP_VOICE           = b'\x80'
PVT_VOICE             = b'\x81'
GROUP_DATA            = b'\x83'
PVT_DATA              = b'\x84'
RPT_WAKE_UP           = b'\x85' # Similar to OTA DMR "wake up"
UNKNOWN_COLLISION     = b'\x86' # Seen when two dmrlinks try to transmit at once
MASTER_REG_REQ        = b'\x90' # FROM peer TO master
MASTER_REG_REPLY      = b'\x91' # FROM master TO peer
PEER_LIST_REQ         = b'\x92' # From peer TO master
PEER_LIST_REPLY       = b'\x93' # From master TO peer
PEER_REG_REQ          = b'\x94' # Peer registration request
PEER_REG_REPLY        = b'\x95' # Peer registration reply
MASTER_ALIVE_REQ      = b'\x96' # FROM peer TO master
MASTER_ALIVE_REPLY    = b'\x97' # FROM master TO peer
PEER_ALIVE_REQ        = b'\x98' # Peer keep alive request
PEER_ALIVE_REPLY      = b'\x99' # Peer keep alive reply
DE_REG_REQ            = b'\x9A' # Request de-registration from system
DE_REG_REPLY          = b'\x9B' # De-registration reply

PEER_OP_MSK       = 0b01000000
PEER_MODE_MSK     = 0b00110000
PEER_MODE_ANALOG  = 0b00010000
PEER_MODE_DIGITAL = 0b00100000
IPSC_TS1_MSK      = 0b00001100
IPSC_TS2_MSK      = 0b00000011

LINK_TYPE_IPSC        = b'\x04'
# IPSC Version Information
IPSC_VER_14           = b'\x00'
IPSC_VER_15           = b'\x00'
IPSC_VER_15A          = b'\x00'
IPSC_VER_16           = b'\x01'
IPSC_VER_17           = b'\x02'
IPSC_VER_18           = b'\x02'
IPSC_VER_19           = b'\x03'
IPSC_VER_22           = b'\x04'

IPSC_VER              = LINK_TYPE_IPSC + IPSC_VER_17 + LINK_TYPE_IPSC + IPSC_VER_16

BURST_DATA_TYPE = {
    'VOICE_HEAD':  b'\x01',
    'VOICE_TERM':  b'\x02',
    'SLOT1_VOICE': b'\x0a',
    'SLOT2_VOICE': b'\x8a'   
}

class RadioSystem:
    LOCAL_ID = b'\x00\x00\x00\x0A'
    MODE = b'\x6A'
    FLAGS = b'\x00\x00\x00\x14'
    TS_FLAGS             = (MODE + FLAGS)
    MASTER_REG_REQ_PKT   = (MASTER_REG_REQ + LOCAL_ID + TS_FLAGS + IPSC_VER)
    MASTER_ALIVE_PKT     = (MASTER_ALIVE_REQ + LOCAL_ID + TS_FLAGS + IPSC_VER)
    PEER_LIST_REQ_PKT    = (PEER_LIST_REQ + LOCAL_ID)
    PEER_REG_REQ_PKT     = (PEER_REG_REQ + LOCAL_ID + IPSC_VER)
    PEER_REG_REPLY_PKT   = (PEER_REG_REPLY + LOCAL_ID + IPSC_VER)
    PEER_ALIVE_REQ_PKT   = (PEER_ALIVE_REQ + LOCAL_ID + TS_FLAGS)
    PEER_ALIVE_REPLY_PKT = (PEER_ALIVE_REPLY + LOCAL_ID + TS_FLAGS)

    def __init__(self, local=None, master=None, authkey=None):
        self.local_addr = local
        self.master_addr = master
        self.authkey = bytes.fromhex((authkey.rjust(40,'0')))
        self.master = None
        self.peers = []
        self.ambe_file = open('ambe2.bin', 'wb')

    def hashed_packet(self, _key, _data):
    #    _log = logger.debug
        _hash = binascii.a2b_hex((hmac.new(_key,_data,hashlib.sha1)).hexdigest()[:20])
    #    _log('Hash for: %s is %s', binascii.b2a_hex(_data), binascii.b2a_hex(_hash)
        return (_data + _hash)    
    

    def processPeers(self, _data):
        #_log = logger.debug
        # Set the status flag to indicate we have recieved a Peer List
        # Determine the length of the peer list for the parsing iterator
        _peer_list_length = int(binascii.b2a_hex(_data[5:7]), 16)
        # Record the number of peers in the data structure... we'll use it later (11 bytes per peer entry)
        #    _log('<<- (%s) The Peer List has been Received from Master\n%s There are %s peers in this IPSC Network', _network, (' '*(len(_network)+7)), _num_peers)
        
        # Iterate each peer entry in the peer list. Skip the header, then pull the next peer, the next, etc.
        for i in range(7, (_peer_list_length)+7, 11):
            # Extract various elements from each entry...
            _hex_radio_id = (_data[i:i+4])
            _hex_address  = (_data[i+4:i+8])
            _ip_address   = socket.inet_ntoa(_hex_address)
            _hex_port     = (_data[i+8:i+10])
            _port         = int(binascii.b2a_hex(_hex_port), 16)
            _hex_mode     = (_data[i+10:i+11])
            _mode         = int(binascii.b2a_hex(_hex_mode), 16)
            # mask individual Mode parameters
            _link_op      = _mode & PEER_OP_MSK
            _link_mode    = _mode & PEER_MODE_MSK
            _ts1          = _mode & IPSC_TS1_MSK
            _ts2          = _mode & IPSC_TS2_MSK    
            
            # Determine whether or not the peer is operational
            if   _link_op == 0b01000000:
                _peer_op = True
            else:
                _peer_op = False
                  
            # Determine the operational mode of the peer
            if   _link_mode == 0b00000000:
                _peer_mode = 'NO_RADIO'
            elif _link_mode == 0b00010000:
                _peer_mode = 'ANALOG'
            elif _link_mode == 0b00100000:
                _peer_mode = 'DIGITAL'
            else:
                _peer_node = 'NO_RADIO'
                
            # Determine whether or not timeslot 1 is linked
            if _ts1 == 0b00001000:
                 _ts1 = True
            else:
                 _ts1 = False
                 
            # Determine whether or not timeslot 2 is linked
            if _ts2 == 0b00000010:
                _ts2 = True
            else:
                _ts2 = False  

            # If this entry was NOT already in our list, add it.
            #     Note: We keep a "simple" peer list in addition to the large data
            #           structure because soemtimes, we just need to identify a
            #           peer quickly.
            self.peers.append({
                'RADIO_ID':  _hex_radio_id, 
                'IP':        _ip_address, 
                'PORT':      _port, 
                'MODE':      _hex_mode,
                'PEER_OPER': _peer_op,
                'PEER_MODE': _peer_mode,
                'TS1_LINK':  _ts1,
                'TS2_LINK':  _ts2,
                'STATUS':    {'CONNECTED': False, 'KEEP_ALIVES_SENT': 0, 'KEEP_ALIVES_MISSED': 0, 'KEEP_ALIVES_OUTSTANDING': 0}
            })


    def connection_made(self, transport):
        self.transport = transport

    def send_peer_alive_response(self, host, port):
        peer_alive_reply_packet = self.hashed_packet(self.authkey, self.PEER_ALIVE_REPLY_PKT)
        self.transport.sendto(peer_alive_reply_packet, (host, port))
    
    def send_peer_registration_response(self, host, port):
        peer_reg_reply_packet = self.hashed_packet(self.authkey, self.PEER_REG_REPLY_PKT)
        self.transport.sendto(peer_reg_reply_packet, (host, port))

    def send_master_registration_request(self):
        reg_packet = self.hashed_packet(self.authkey, self.MASTER_REG_REQ_PKT)
        self.transport.sendto(reg_packet, (self.master_addr))

    def send_master_peers_request(self):
        peer_list_req_packet = self.hashed_packet(self.authkey, self.PEER_LIST_REQ_PKT)
        self.transport.sendto(peer_list_req_packet, (self.master_addr))

    def strip_hash(self, _data):
        return _data[:-10]

    def group_voice(self, data):
        _payload_type = data[30:31]
        _ambe_frames = BitArray(b'\0x'+binascii.b2a_hex(data[33:52])) 
        _ambe_frame1 = _ambe_frames[0:49]
        _ambe_frame2 = _ambe_frames[50:99]
        _ambe_frame3 = _ambe_frames[100:149]

        #self.ambe_file.write(_ambe_frame1.tobytes())
        #self.ambe_file.write(_ambe_frame2.tobytes())
        #self.ambe_file.write(_ambe_frame3.tobytes())
        if _payload_type == BURST_DATA_TYPE['VOICE_HEAD']:
            print("VOICE_HEAD")
        elif _payload_type == BURST_DATA_TYPE['VOICE_TERM']:
            print("VOICE_TERM") 
        elif _payload_type == BURST_DATA_TYPE['SLOT1_VOICE']:
            print("SLOT1_VOICE") 
        elif _payload_type == BURST_DATA_TYPE['SLOT2_VOICE']:
            print("SLOT2_VOICE")    
            self.ambe_file.write(data[33:52])    
            self.ambe_file.close()
        print("AMBE:" , _ambe_frames)  
        

    def datagram_received(self, data, addr):
        print('Received %r from %s' % (data, addr))
        (host, port) = addr
        _packettype = data[0:1]
        _peerid     = data[1:5]
        _ipsc_seq   = data[5:6]
        _dec_peerid = int(binascii.b2a_hex(_peerid), 16)

        data = self.strip_hash(data)

        if (_packettype == GROUP_VOICE):
            self.group_voice(data)
            #print("GROUP_VOICE", data, addr)

        elif (_packettype in [CALL_MON_STATUS, CALL_MON_RPT, CALL_MON_NACK]):
            print("CALL_MON_STATUS")


        # IPSC keep alives, master and peer, come next in processing priority
        #
        elif (_packettype == PEER_ALIVE_REQ):
            print("PEER_ALIVE_REQ", _dec_peerid)
            self.send_peer_alive_response(host, port)

        elif (_packettype == MASTER_ALIVE_REPLY):
            # We should not accept keep-alive reply from someone claming to be a master who isn't!
            if valid_master(self._network, _peerid) == False:
                logger.warning('(%s) PeerError: Peer %s not in peer-list: %s', self._network, _dec_peerid, self._peer_list)
                return
                 
            # logger.debug('<<- (%s) Master Keep-alive Reply From: %s \t@ IP: %s:%s', self._network, _dec_peerid, host, port)
            # This action is so simple, it doesn't require a callback function, master is responding, we're good.
            self._master_stat['KEEP_ALIVES_OUTSTANDING'] = 0

        elif (_packettype == PEER_ALIVE_REPLY):
            print("PEER_ALIVE_REPLY")
            # Find the peer in our list of peers...
            for peer in self._config['PEERS']:
                if peer['RADIO_ID'] == _peerid:
                    # No callback funcntion needed, set the outstanding keepalives to 0, and move on.
                    peer['STATUS']['KEEP_ALIVES_OUTSTANDING'] = 0     
        
        # Registration requests and replies are infrequent, but important. Peer lists can go here too as a part
        # of the registration process.
        #    
        elif (_packettype == MASTER_REG_REQ):
            # We can't operate as a master as of now, so we should never receive one of these.
            # logger.debug('<<- (%s) Master Registration Packet Recieved', self._network)
            pass

        # When we hear from the maseter, record it's ID, flag that we're connected, and reset the dead counter.
        elif (_packettype == MASTER_REG_REPLY):
            print("MASTER_REG_REPLY")
            self.master = _peerid
        
        # Answer a peer registration request -- simple, no callback runction needed
        elif (_packettype == PEER_REG_REQ):
            print("PEER_REG_REQ")
            self.send_peer_registration_response(host, port)

        elif (_packettype == PEER_REG_REPLY):
            print("PEER_REG_REPLY")
            for peer in self._config['PEERS']:
                if peer['RADIO_ID'] == _peerid:
                    peer['STATUS']['CONNECTED'] = True

        elif (_packettype == PEER_LIST_REPLY):
            if len(data) > 18:
                self.processPeers(data)
            else:
                NETWORK[self._network]['MASTER']['STATUS']['PEER-LIST'] = True
 
        elif (_packettype == DE_REG_REQ):
            de_register_peer(self._network, _peerid)
            logger.warning('<<- (%s) Peer De-Registration Request From:%s:%s', self._network, host, port)
            
        elif (_packettype == DE_REG_REPLY):
            logger.warning('<<- (%s) Peer De-Registration Reply From:%s:%s', self._network, host, port)
            
        elif (_packettype == RPT_WAKE_UP):
            logger.warning('<<- (%s) Repeater Wake-Up Packet From:%s:%s', self._network, host, port)

    def connection_lost(self, blag):
        self.ambe_file.close()
        print("blagsdsdsd")

    def worker(self, loop):
        if not self.master:
            self.send_master_registration_request()

        if self.master and not self.peers:
            self.send_master_peers_request()

        loop.call_later(3, self.worker, loop)


async def main():
    ipsc = RadioSystem(
        local=('10.187.15.222', 50010),
        master=('10.187.243.2', 50000),
        authkey='C602EE7C43784956F7C25254A38E4E7DA2535CD4'
    )

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ipsc, local_addr=ipsc.local_addr)
    loop.call_soon(ipsc.worker, loop)
    try:
        await asyncio.Event().wait()  # wait here until the Universe ends
    finally:
        transport.close()


asyncio.run(main())