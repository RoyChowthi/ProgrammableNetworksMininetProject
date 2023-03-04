# Assignment 2 Skeleton

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.packet import ipv4
from pox.lib.addresses import EthAddr
from pox.lib.packet import ethernet


log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    ftable = of.ofp_flow_mod()
    compare = of.ofp_match()
    compare.d1_type = packet.type
    if compare.d1_type == ethernet.ip_type:
      protocol = packet.payload.protocol
      compare.nw_proto = protocol
      ftable.priority = 1
      if protocol == ipv4.TCP_PROTOCOL:
        print("Accept Packet")
        ftable.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        ftable.priority = 100
      else:
        None
    elif compare.dl_type == ethernet.ARP_TYPE:
        print("Accept Packet")
        ftable.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        ftable.priority = 100
    else:
        print("Drop Packets")
        ftable.priority = 1
    ftable.match = match
    self.connection.send(ftable)
          
    print "Example Code."

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
