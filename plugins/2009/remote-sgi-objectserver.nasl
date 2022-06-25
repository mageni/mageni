###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-sgi-objectserver.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# SGI-objectserver
# replaces objectserver C plugin
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80101");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-14 09:49:01 +0100 (Sat, 14 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_copyright("(C) 2009 Vlatko Kosturjak");
  script_name("SGI Objectserver vuln");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_dependencies("global_settings.nasl");
  script_require_udp_ports(5135);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"summary", value:"IRIX object server is installed on this host.

  There are various security bugs in the implementation of this service which can
  be used by an intruder to gain a root account rather easily.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

if(TARGET_IS_IPV6())exit(0);

port = 5135;
if( ! get_udp_port_state( port ) ) exit(0);

numer_one = raw_string(0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00, 0x00,0x00,0x00,0x24,0x00,0x00,0x00,0x00);
numer_two = raw_string(0x21,0x03,0x00,0x43,0x00,0x0a,0x00,0x0a, 0x01,0x01,0x3b,0x01,0x6e,0x00,0x00,0x80, 0x43,0x01,0x01,0x18,0x0b,0x01,0x01,0x3b, 0x01,0x6e,0x01,0x02,0x01,0x03,0x00,0x01, 0x01,0x07,0x01,0x01);

targetip = get_host_ip();

ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0,
                     ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
                     ip_src: this_host());

sport = rand() % 64512 + 1024;
req = numer_one + numer_two;

u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);
filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + '';

gotresp = 0;
gotvuln = 0;

for (i = 0; i < 2; i ++) # Try twice
{
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
  if(rep) {
    gotresp = 1;
    data = get_udp_element(udp: rep, element:"data");
    cmpdata=raw_string(0x0a,0x01,0x01,0x3b,0x01,0x78);
    if (cmpdata >< data) {
      gotvuln = 1;
    }
  }
}

if (gotresp ==1 ) {
  register_service(port: port, ipproto: "udp", proto: "objectserver");
}

if (gotvuln == 1) {
  security_message(port:port, proto: "udp");
}

exit (0);