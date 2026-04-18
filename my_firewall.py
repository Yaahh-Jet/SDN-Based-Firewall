from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()

class Firewall (object):
    def __init__ (self):
        # Listen to connections from switches
        core.openflow.addListeners(self)
        
        # RULES: List of (Src_IP, Dst_IP) to block
        self.blocked_pairs = [
            ("10.0.0.1", "10.0.0.2"), # Block H1 -> H2
        ]

    def _handle_PacketIn (self, event):
        packet = event.parsed
        if not packet.parsed: return

        # Look for IPv4 traffic
        ip_pkt = packet.find('ipv4')
        
        if ip_pkt:
            src_ip = str(ip_pkt.srcip)
            dst_ip = str(ip_pkt.dstip)

            # 1. CHECK BLOCK RULES
            for (b_src, b_dst) in self.blocked_pairs:
                if src_ip == b_src and dst_ip == b_dst:
                    log.info("!!! FIREWALL DROP: %s -> %s !!!", src_ip, dst_ip)
                    
                    # 2. INSTALL DROP RULE (Flow Modification)
                    msg = of.ofp_flow_mod()
                    msg.match.dl_type = 0x0800 # Match IPv4
                    msg.match.nw_src = IPAddr(src_ip)
                    msg.match.nw_dst = IPAddr(dst_ip)
                    msg.idle_timeout = 30      # Rule expires in 30s
                    # No actions added = Packet is dropped
                    event.connection.send(msg)
                    return

        # 3. ALLOWED TRAFFIC: Flood to all ports (Act like a hub)
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        event.connection.send(msg)

def launch ():
    core.registerNew(Firewall)
