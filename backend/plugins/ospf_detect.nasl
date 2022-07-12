###############################################################################
# OpenVAS Vulnerability Test
#
# OSPF Agent Detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# RFC 1247 / RFC 2328 (OSPF v2)
# The OSPF protocol runs directly over IP, using IP protocol 89.
# Routing protocol packets should always be sent with the IP TOS field set to 0.
#
# Table 8: OSPF packet types.
#    1      Hello                  Discover/maintain  neighbors
#    2      Database Description   Summarize database contents
#    3      Link State Request     Database download
#    4      Link State Update      Database update
#    5      Link State Ack         Flooding acknowledgment

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11906");
  script_version("2020-04-20T12:21:14+0000");
  script_tag(name:"last_modification", value:"2020-04-21 10:11:05 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OSPF Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("global_settings.nasl");
  script_mandatory_keys("keys/islocalnet");
  script_exclude_keys("keys/islocalhost");

  script_tag(name:"summary", value:"The remote host is running an OSPF (Open Shortest Path First) agent.");

  script_tag(name:"solution", value:"If the remote service is not used, disable it.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

if(islocalhost() || !islocalnet())
  exit(0);

# nb: join_multicast_group is necessary, because pcap_next does not put the interface in promiscuous mode.
if(TARGET_IS_IPV6()) {
  joined_five = join_multicast_group("ff02::5"); # AllSPFRouters
  joined_six = join_multicast_group("ff02::6"); # AllDRouters
} else {
  joined_five = join_multicast_group("224.0.0.5"); # AllSPFRouters
  joined_six = join_multicast_group("224.0.0.6"); # AllDRouters
}

function on_exit() {
  if(TARGET_IS_IPV6()) {
    if(!isnull(joined_five))
      leave_multicast_group("ff02::5");
    if(!isnull(joined_six))
      leave_multicast_group("ff02::6");
  } else {
    if(!isnull(joined_five))
      leave_multicast_group("224.0.0.5");
    if(!isnull(joined_six))
      leave_multicast_group("224.0.0.6");
  }
}

function extract_ip_addr(pkt, off) {

  local_var pkt, off;

  # This avoids a dirty warning, but there is definitely a problem somewhere
  # Why do I receive short OSPF Hello packets?
  if(off + 4 > strlen(pkt))
    return '0.0.0.0';

  return strcat(ord(pkt[off+0]), ".",
                ord(pkt[off+1]), ".",
                ord(pkt[off+2]), ".",
                ord(pkt[off+3]));
}

f = "ip proto 89 and src " + get_host_ip();
p = pcap_next(pcap_filter:f, timeout:5);
if(isnull(p))
  exit(0);

hl = ord(p[0]) & 0xF;
hl *= 4;
ospf = substr(p, hl);

head = substr(ospf, 0, 24);
data = substr(ospf, 24);

# OSPF header
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   Version #   |     Type      |         Packet length         |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          Router ID                            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                           Area ID                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |           Checksum            |             AuType            |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Authentication                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                       Authentication                          |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ver = ord(head[0]);
type = ord(head[1]);
len = ord(head[2]) * 256 + ord(head[3]);
rep = strcat('\nAn OSPF v', ver, ' agent is running on this host.\n');

# OSPF Hello packet
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                        Network Mask                           |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |         HelloInterval         |    Options    |    Rtr Pri    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                     RouterDeadInterval                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Designated Router                        |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                   Backup Designated Router                    |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                          Neighbor                             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

if(type == 1) {
  mask = extract_ip_addr(pkt:data, off:0);
  rep += strcat('The netmask is ', mask, '\n');
  dr = extract_ip_addr(pkt:data, off:12);
  if(dr != '0.0.0.0')
    rep += strcat('The Designated Router is ', dr, '\n');
  bdr = extract_ip_addr(pkt:data, off:16);
  if(bdr != '0.0.0.0')
    rep += strcat('The Backup Designated Router is ', dr, '\n');
  n = extract_ip_addr(pkt:data, off:20);
  if(n != '0.0.0.0')
    rep += strcat('Neighbor ', n, ' has been seen\n');
}

log_message(port:0, protocol:"ospf", data:rep);
exit(0);
