from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet.ethernet as pkt
from pox.lib.addresses import IPAddr
# from pox.lib.packet import *


log = core.getLogger()

class Tutorial (object):
  def __init__ (self, connection):

    self.connection = connection
    connection.addListeners(self)
    self.mac_to_port = {}

  def act_like_hub (self, packet, packet_in):

    self.resend_packet(packet_in, of.OFPP_ALL)


  def act_like_switch (self, packet, packet_in):

    # print("Msg from " + str(packet.src) + "to " + str(packet.dst) + "at switch " + packet_in.src)

    if str(packet.src) not in self.mac_to_port:
      # print "Learning that " + str(packet.src) + " is attached at port " + str(packet_in.in_port)
      self.mac_to_port[str(packet.src)] = packet_in.in_port
      # print "Src: ",str(packet.src),",      In Port: ", packet_in.in_port,",        Dst:", str(packet.dst)

      print(str(packet.src))
      txt = "00-00-00-00-00-01"

      # x is dpid of switch
      x = str(int(txt.replace("-","")))

      # txt is packet.src
      print("s"+ x + ", 00:00:00:00:00:01")


    if(str(packet.dst) in self.mac_to_port):

      dst_in_port = self.mac_to_port[str(packet.dst)]
      self.resend_packet(packet_in, dst_in_port)

      msg = of.ofp_flow_mod()
      
      msg.match = of.ofp_match.from_packet(packet)
     
      action = of.ofp_action_output(port=dst_in_port)
      msg.actions.append(action)

      self.connection.send(msg)

    else:
      self.resend_packet(packet_in, of.OFPP_ALL)


  def _handle_PacketIn (self, event):

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.

    # self.act_like_hub(packet, packet_in)

    # self.act_like_switch(packet, packet_in)


    # Set flood arp packet and send action to switch so that host can find mac of destination
    if(packet.type == pkt.ARP_TYPE):

      msg = of.ofp_packet_out()
      msg.data = packet_in
      action = of.ofp_action_output(port = of.OFPP_FLOOD)
      msg.actions.append(action)
      self.connection.send(msg)

      msg = of.ofp_flow_mod()
      msg.match.dl_type = 0x806
      action = of.ofp_action_output(port =of.OFPP_FLOOD)
      msg.actions.append(action)
      self.connection.send(msg)


    if(packet.type == pkt.IP_TYPE):

      # # traffic between h1 and h3
      if((str(packet.payload.srcip) == "10.0.0.1" and str(packet.payload.dstip) == "10.0.0.3") or (str(packet.payload.srcip) == "10.0.0.3" and str(packet.payload.dstip) == "10.0.0.1")):
        
          # no action therefore dropped
          msg = of.ofp_packet_out()
          msg.data = packet_in
          self.connection.send(msg)

          print("traffic between h1 and h3 is not allowed")
          return

      # # traffic between h3 and h2  
      if((str(packet.payload.srcip) == "10.0.0.2" and str(packet.payload.dstip) == "10.0.0.3") or (str(packet.payload.srcip) == "10.0.0.3" and str(packet.payload.dstip) == "10.0.0.2")):
          # call s3 function
          self.traffic_h3_h2(packet, packet_in, event)
          return

      # # non http traffic between h1 and h4
      if((str(packet.payload.srcip) == "10.0.0.1" and str(packet.payload.dstip) == "10.0.0.4") or (str(packet.payload.srcip) == "10.0.0.4" and str(packet.payload.dstip) == "10.0.0.1")):

        self.traffic_h1_h4(packet, packet_in, event)
        return

  def traffic_h1_h4(self, packet, packet_in, event):

    switch_no = str(int(dpid_to_str(event.dpid).replace("-","")))

    # shortcircuit if udp or tcp traffic then go to and condition which is to check port of http i.e. 80
    # if neither udp or tcp then will not check http port condition
    if((str(packet.payload.protocol) == "6" or str(packet.payload.protocol) == "17") and str(packet.payload.payload.dstport) == "80"):

      # route through s2
      print('route s2')

      if(switch_no == "1"):

        if(str(packet.payload.dstip) == "10.0.0.4"):

          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 9)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 9)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x0800
          # msg.match.nw_proto = 6
          # msg.match.tp_dst = 80
          # msg.match.nw_src = IPAddr("10.0.0.1")
          # msg.match.nw_dst = IPAddr("10.0.0.4")
          # action = of.ofp_action_output(port =9)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.1"), IPAddr("10.0.0.4"), 9, 6, 80, 0x800)


        elif(str(packet.payload.dstip) == "10.0.0.1"):
        
          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 2)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 2)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x0800
          # msg.match.nw_proto = 6
          # msg.match.tp_dst = 80
          # msg.match.nw_src = IPAddr("10.0.0.4")
          # msg.match.nw_dst = IPAddr("10.0.0.1")
          # action = of.ofp_action_output(port =2)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.4"), IPAddr("10.0.0.1"), 2, 6, 80, 0x800)


      if(switch_no == "2"):

        if(str(packet.payload.dstip) == "10.0.0.4"):

          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 11)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 11)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x0800
          # msg.match.nw_proto = 6
          # msg.match.tp_dst = 80
          # msg.match.nw_src = IPAddr("10.0.0.1")
          # msg.match.nw_dst = IPAddr("10.0.0.4")
          # action = of.ofp_action_output(port =11)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.1"), IPAddr("10.0.0.4"), 11, 6, 80, 0x800)


        elif(str(packet.payload.dstip) == "10.0.0.1"):
        
          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 10)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 10)
  

          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x0800
          # msg.match.nw_proto = 6
          # msg.match.tp_dst = 80
          # msg.match.nw_src = IPAddr("10.0.0.4")
          # msg.match.nw_dst = IPAddr("10.0.0.1")
          # action = of.ofp_action_output(port =10)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.4"), IPAddr("10.0.0.1"), 10, 6, 80, 0x800)


      if(switch_no == "4"):

        if(str(packet.payload.dstip) == "10.0.0.4"):

          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 8)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 8)

          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x0800
          # msg.match.nw_proto = 6
          # msg.match.tp_dst = 80
          # msg.match.nw_src = IPAddr("10.0.0.1")
          # msg.match.nw_dst = IPAddr("10.0.0.4")
          # action = of.ofp_action_output(port =8)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.1"), IPAddr("10.0.0.4"), 8, 6, 80, 0x800)


        elif(str(packet.payload.dstip) == "10.0.0.1"):
        
          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port =12)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 12)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x0800
          # msg.match.nw_proto = 6
          # msg.match.tp_dst = 80
          # msg.match.nw_src = IPAddr("10.0.0.4") 
          # msg.match.nw_dst = IPAddr("10.0.0.1")
          # action = of.ofp_action_output(port =12)
          # msg.actions.append(action)
          # self.connection.send(msg) 
          self.flow_mod(IPAddr("10.0.0.4"), IPAddr("10.0.0.1"), 12, 6, 80, 0x800)


    else:
      # non http traffic
      # route through s3
      print("route s3")

      if(switch_no == "1"):

        if(str(packet.payload.dstip) == "10.0.0.4"):

          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 13)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 13)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x800
          # msg.match.nw_src = IPAddr("10.0.0.1")
          # msg.match.nw_dst = IPAddr("10.0.0.4")
          # action = of.ofp_action_output(port =13)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.1"), IPAddr("10.0.0.4"), 13, None, None, 0x800)


        elif(str(packet.payload.dstip) == "10.0.0.1"):
        
          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 2)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 2)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x800
          # msg.match.nw_src = IPAddr("10.0.0.4")
          # msg.match.nw_dst = IPAddr("10.0.0.1")
          # action = of.ofp_action_output(port =2)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.4"), IPAddr("10.0.0.1"), 2, None, None, 0x800)


      if(switch_no == "3"):

        if(str(packet.payload.dstip) == "10.0.0.4"):

          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 15)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 15)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x800
          # msg.match.nw_src = IPAddr("10.0.0.1")
          # msg.match.nw_dst = IPAddr("10.0.0.4")
          # action = of.ofp_action_output(port =15)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.1"), IPAddr("10.0.0.4"), 15, None, None, 0x800)


        elif(str(packet.payload.dstip) == "10.0.0.1"):
        
          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 14)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 14)
  

          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x800
          # msg.match.nw_src = IPAddr("10.0.0.4")
          # msg.match.nw_dst = IPAddr("10.0.0.1")
          # action = of.ofp_action_output(port =14)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.4"), IPAddr("10.0.0.1"), 14, None, None, 0x800)


      if(switch_no == "4"):

        if(str(packet.payload.dstip) == "10.0.0.4"):

          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port = 8)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 8)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x800
          # msg.match.nw_src = IPAddr("10.0.0.1")
          # msg.match.nw_dst = IPAddr("10.0.0.4")
          # action = of.ofp_action_output(port =8)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.1"), IPAddr("10.0.0.4"), 8, None, None, 0x800)


        elif(str(packet.payload.dstip) == "10.0.0.1"):
        
          # msg = of.ofp_packet_out()
          # msg.data = packet_in
          # action = of.ofp_action_output(port =16)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.send_Packet(packet_in, 16)


          # msg = of.ofp_flow_mod()
          # msg.match.dl_type = 0x800
          # msg.match.nw_src = IPAddr("10.0.0.4") 
          # msg.match.nw_dst = IPAddr("10.0.0.1")
          # action = of.ofp_action_output(port =16)
          # msg.actions.append(action)
          # self.connection.send(msg)
          self.flow_mod(IPAddr("10.0.0.4"), IPAddr("10.0.0.1"), 16, None, None, 0x800)


  def traffic_h3_h2(self, packet, packet_in, event):

    switch_no = str(int(dpid_to_str(event.dpid).replace("-","")))

    if(switch_no == "1"):

      if(str(packet.payload.dstip) == "10.0.0.3"):

        # msg = of.ofp_packet_out()
        # msg.data = packet_in
        # action = of.ofp_action_output(port = 13)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.send_Packet(packet_in, 13)


        # msg = of.ofp_flow_mod()
        # msg.match.dl_type = 0x800
        # msg.match.nw_src = IPAddr("10.0.0.2")
        # msg.match.nw_dst = IPAddr("10.0.0.3")
        # action = of.ofp_action_output(port =13)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.flow_mod(IPAddr("10.0.0.2"), IPAddr("10.0.0.3"), 13, None, None, 0x800)


      elif(str(packet.payload.dstip) == "10.0.0.2"):
        
        # msg = of.ofp_packet_out()
        # msg.data = packet_in
        # action = of.ofp_action_output(port = 4)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.send_Packet(packet_in, 4)



        # msg = of.ofp_flow_mod()
        # msg.match.dl_type = 0x800
        # msg.match.nw_src = IPAddr("10.0.0.3")
        # msg.match.nw_dst = IPAddr("10.0.0.2")
        # action = of.ofp_action_output(port =4)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.flow_mod(IPAddr("10.0.0.3"), IPAddr("10.0.0.2"), 4, None, None, 0x800)


    if(switch_no == "3"):

      if(str(packet.payload.dstip) == "10.0.0.3"):

        # msg = of.ofp_packet_out()
        # msg.data = packet_in
        # action = of.ofp_action_output(port = 15)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.send_Packet(packet_in, 15)


        # msg = of.ofp_flow_mod()
        # msg.match.dl_type = 0x800
        # msg.match.nw_src = IPAddr("10.0.0.2")
        # msg.match.nw_dst = IPAddr("10.0.0.3")
        # action = of.ofp_action_output(port =15)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.flow_mod(IPAddr("10.0.0.2"), IPAddr("10.0.0.3"), 15, None, None, 0x800)


      elif(str(packet.payload.dstip) == "10.0.0.2"):
        
        # msg = of.ofp_packet_out()
        # msg.data = packet_in
        # action = of.ofp_action_output(port = 14)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.send_Packet(packet_in, 14)


        # msg = of.ofp_flow_mod()
        # msg.match.dl_type = 0x800
        # msg.match.nw_src = IPAddr("10.0.0.3")
        # msg.match.nw_dst = IPAddr("10.0.0.2")
        # action = of.ofp_action_output(port =14)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.flow_mod(IPAddr("10.0.0.3"), IPAddr("10.0.0.2"), 14, None, None, 0x800)


    if(switch_no == "4"):

      if(str(packet.payload.dstip) == "10.0.0.3"):

        # msg = of.ofp_packet_out()
        # msg.data = packet_in
        # action = of.ofp_action_output(port = 6)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.send_Packet(packet_in, 6)

        # msg = of.ofp_flow_mod()
        # msg.match.dl_type = 0x800
        # msg.match.nw_src = IPAddr("10.0.0.2")
        # msg.match.nw_dst = IPAddr("10.0.0.3")
        # action = of.ofp_action_output(port =6)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.flow_mod(IPAddr("10.0.0.2"), IPAddr("10.0.0.3"), 6, None, None, 0x800)


      elif(str(packet.payload.dstip) == "10.0.0.2"):
        
        # msg = of.ofp_packet_out()
        # msg.data = packet_in
        # action = of.ofp_action_output(port =16)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.send_Packet(packet_in, 16)


        # msg = of.ofp_flow_mod()
        # msg.match.dl_type = 0x800
        # msg.match.nw_src = IPAddr("10.0.0.3") 
        # msg.match.nw_dst = IPAddr("10.0.0.2")
        # action = of.ofp_action_output(port =16)
        # msg.actions.append(action)
        # self.connection.send(msg)
        self.flow_mod(IPAddr("10.0.0.3"), IPAddr("10.0.0.2"), 16, None, None, 0x800)

  def flow_mod (self, src_ip_adr, dst_ip_adr, port_no, tp_dst_no, nw_protocol, dl_type_no):
  	msg = of.ofp_flow_mod()
  	if dl_type is not None:
  		msg.match.dl_type = dl_type_no
  		msg.match.nw_src = src_ip_adr
  		msg.match.nw_dst = dst_ip_adr

  	if(tp_dst is not None):
  		msg.match.tp_dst = tp_dst_no
  	if(nw_proto is not None):
  		msg.match.nw_proto = nw_protocol

  	action = of.ofp_action_output(port =port_no)
  	msg.actions.append(action)
  	self.connection.send(msg)


  def resend_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def send_Packet (self, packet_in, port_no):

  	msg = of.ofp_packet_out()
  	msg.data = packet_in
  	action = of.ofp_action_output(port = port_no)
  	msg.actions.append(action)
  	self.connection.send(msg)


def launch ():

  def start_switch (event):
    # log.info("Controlling %s" % (event.connection,))
    # log.info("Switch %s has come up.", dpid_to_str(event.dpid))
    Tutorial(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)
