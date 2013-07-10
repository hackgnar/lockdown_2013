from scapy.packet import bind_layers, Packet
from scapy.layers.l2 import Ether
from scapy.fields import XBitField, BitField, XByteField, StrLenField
from scapy.fields import BitEnumField
from scapy.utils import RawPcapReader
from scapy.data import MTU
import struct
import time
import os
import re

class Btbb(Packet):
    """Top level wrapper packet class for bluetooth baseband packets.  All
    child sections of this top level wrapper class organize the content of
    bluetooth baseband packets.
    """
    name = 'btbb'
    fields_desc = []

direction = {"Slave to Master":0, "Master to Slave":1}
address_bits = {"32 (NAP unknown)":0,"48 (NAP known)":1}
clock_bits = {"6":0,"27":1}

class BtbbMeta(Packet):
    """Bluetooth baseband packet class for bluetooth baseband meta data.
    Bluetooth baseband meta data defines a packets channel, padding, along
    with bool flags indicating wether or not the upper bluetooh address and
    clock bits are know.
    """
    name = 'meta'
    fields_desc = [ XBitField('CLK', 0, 32),
            #Not sure how to display this as direction is derived from CLK
            #BitEnumField("direction", 1, 1, direction),
            BitField('Channel',0, 8),
            BitField('Padding', 0, 6),
            BitEnumField("known address bits", 0, 1, address_bits),
            BitEnumField("known clock bits", 0, 1, clock_bits),
            ]

btbb_packet_type = { 0: "NULL",
    1: "POLL",
    2: "FHS",
    3: "DM1", 
    4: "DH1/2-DH1",
    5: "HV1",
    6: "HV2/2-EV3",
    7: "HV3/EV3/3-EV3",
    8: "DV/3-DH1",
    9: "AUX1",
    10: "DM3/2-DH3",
    11: "DH3/3-DH3",
    12: "EV4/2-EV5",
    13: "EV5/3-EV5",
    14: "DM5/2-DH5",
    15: "DH5/3-DH5"}

class BtbbPacket(Packet):
    """Bluetooth baseband packet class for bluetooth baseband packet header
    data. Bluetooth baseband packet header data defines a packets type and
    header flags.
    """
    name = 'packet'
    fields_desc = [ BitEnumField('type', 0, 5, btbb_packet_type),
            XBitField('LT_ADDR',0, 3),
            BitField('SEQN_Flag', 0, 6),
            BitField('ARQN_Flag', 0, 1),
            BitField('FLOW_Flag', 0, 1),
            XByteField('HEC', 0)
            ]

class BtbbPayload(Packet):
    """Bluetooth baseband packet class for bluetooth baseband payload.
    Bluetooth baseband payload defines the direction of the packet (header 
    flow), the actual baseband payload and finaly a crc check on the payload.
    """
    name = 'payload'
    fields_desc = [ BitField('header_length', 0, 5),
            BitField('header_flow', 0, 1),
            BitField('header_LLID', 0, 2),
            #Body n bytes
            StrLenField("body","", length_from=lambda x:x.header_length),
            #CRC 2 bytes
            XBitField('CRC', 0, 16),
            ]

bind_layers(Ether, Btbb, type=0xfff0) 
bind_layers(Btbb, BtbbMeta, ) 
bind_layers(BtbbMeta, BtbbPacket, ) 
bind_layers(BtbbPacket, BtbbPayload, ) 

def nap_uap_to_int(nap_uap):
    """A crappy helper method to convert the upper address portion of a 
    bluetooth baseband address to an integer so it can be compaired with
    greater than and less than conditionals
    """
    result = '0x' + nap_uap.replace(':', '')
    return int(result, 16)

def get_vendor(btaddr, manuf_file=None):
    """A helper method to identify vendors associated with a bluetooth address.
    This method will attempt to identify a vendor based on an address, but if
    the nap of the address is still unknown, it will return a list of possible
    vendors.  This narrowed list will typicaly reduce possible vendors to a set
    of 30-60 vendors out of the typical 20,000+ known vendors.

    This method uses wiresharks manuf file which is typicaly installed on 
    systems doing network analysis.

    Parameters
    ----------
    btaddr: this can be either a string representation of a bluetooth address,
        or a scapy btbb instansiated packet.
    manuf_file:  If your wireshark manuf file is not in a typical location, it
        can be specified here.
    """
    file_locs=["/etc/manuf",
            "/usr/share/wireshark/wireshark/manuf",
            "/usr/share/wireshark/manuf"]
    if manuf_file:
        file_locs = [manuf_file] + file_locs
    mfile = None
    for loc in file_locs:
        mfile = loc if os.path.exists(loc) else None
        if mfile:
            break
    if not mfile:
        raise Exception

    #vendor = None
    if type(btaddr) == Ether:
        pico = btaddr["Ethernet"].src
    else:
        pico = btaddr

    uap=pico.split(':')[2]
    nap=':'.join(pico.split(':')[:2])
    if nap == '00:00':
        upper='([0-9A-F]{2}:[0-9A-F]{2}:%s)\s+(\w+)' % (uap.upper())
    else:
        upper='(%s:%s)\s+(\w+)' % (nap.upper(), uap.upper())
    f = open(mfile)
    text = f.read()
    f.close()
    matches = re.findall(upper, text)
    return matches


def get_btaddress(*args):
    """Helper function to return a list of unique bt addresses found in a scapy
    btbb packet list.

    Parameters
    ----------
    args: a list of instansiated scapy btbb packets
    """
    picos = {}
    for pkt in args:
        addr = pkt["Ethernet"].src
        addr = addr.split(":")
        lap = ':'.join(addr[3:])
        nap_uap = ':'.join(addr[:3])
        if lap in picos and nap_uap_to_int(nap_uap) > nap_uap_to_int(picos[lap]):
            picos[lap]=nap_uap
        else:
            picos[lap]=nap_uap
    result = [':'.join([v, k]) for k, v in picos.iteritems()]
    return result

#This could/should go in core scapy.utils along with RawPcapReader, etc
class BtbbPcapStreamer(RawPcapReader):
    """A class to create a continuous stream from a pcap file based on scapy's
    RawPcapReader class.  Think of this class as "tail -f" that returns scapy
    objects for pcap files.
    """
    def __init__(self, filename):
        """Create a stream object on a pcap file.  The file can be kept open and
        new data written to the file can be accessed via this classes built in
        methods

        Parameters:
        ----------
        filename:  The pcap file to be streamed.
        """
        self.file_loc = None
        RawPcapReader.__init__(self, filename)

    def stream(self, size=MTU, output='pcap', stop=False):
        """A generator object to continuously return data from a pcap file.
        This method supports multiple output formats such as full pcap, raw
        pcap and scapy packets.  The method can be configured to stop iteration
        once the end of the file has been reached or it can stream forever until
        a ctrl-c event happens.  Also note, this method stores the last location
        accessed in a file and continues from this location on subsequent calls.
        
        Parameters:
        -----------
        size:  The MTU for the pcap objects.  Defaults to scapy's builtin MTU
        output:  The format in which the data will be returned.  Currently, the
            method supports three values (pcap, raw, packet).  Pcap mode outputs
            a tuple with the full pcap data.  Raw mode outputs just the raw
            string data contained in the pcap object.  Packet mode outputs the
            data as an instansiated scapy packet object.
        stop:  Should the generator stop when it gets to the end of the file or
            keep going until a keyboard interupt is detected.
        """
        while True:
            header_loc = self.f.tell()
            try:
                hdr = self.f.read(16)
                
                while len(hdr) < 16:
                    self.f.seek(header_loc)
                    if stop:
                        raise KeyboardInterrupt
                    time.sleep(1)
                    hdr = self.f.read(16)
                
                sec,usec,caplen,wirelen = struct.unpack(self.endian+"IIII", hdr)
                body_loc = self.f.tell()
                s = self.f.read(caplen)[:MTU]
                
                while len(s) < caplen:
                    self.f.seek(body_loc)
                    if stop:
                        raise KeyboardInterrupt
                    time.sleep(1)
                    s = self.f.read(caplen)[:MTU]
                
                result = s,(sec,usec,wirelen)
                if output == 'raw':
                    result = s
                elif output == 'packet':
                    result = Ether(s)
                yield result
            except KeyboardInterrupt:
                self.f.seek(header_loc)
                break

    def read_packet(self, size=MTU, output='pcap'):
        """Reads a single pcap object from the corisponding file and returns it
        in the defined format.  This method is an overload of the parent class
        so the __iter__ method uses this instead.
        
        Parameters:
        -----------
        size:  The MTU for the pcap objects.  Defaults to scapy's builtin MTU
        output:  The format in which the data will be returned.  Currently, the
            method supports three values (pcap, raw, packet).  Pcap mode outputs
            a tuple with the full pcap data.  Raw mode outputs just the raw
            string data contained in the pcap object.  Packet mode outputs the
            data as an instansiated scapy packet object.
        """
        try:
            result = self.stream(stop=True, output=output).next()
        except:
            result = None
        return result

    def read_all(self,count=-1, output='pcap'):
        """returns a list of pcap objects from the corisponding file in the 
        format specified by the output argument.
        
        Parameters:
        -----------
        count:  A limit as to how many pcap objects should be returned from the
            file.  This will be a positive interger corisponding to the length
            of the retunred list.
        output:  The format in which the data will be returned.  Currently, the
            method supports three values (pcap, raw, packet).  Pcap mode outputs
            a tuple with the full pcap data.  Raw mode outputs just the raw
            string data contained in the pcap object.  Packet mode outputs the
            data as an instansiated scapy packet object.
        """
        res=[]
        while count != 0:
            count -= 1
            p = self.read_packet(output=output)
            if p is None:
                break
            res.append(p)
        return res

