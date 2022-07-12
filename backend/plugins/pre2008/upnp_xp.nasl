###############################################################################
# OpenVAS Vulnerability Test
#
# scan for UPNP hosts
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2001 by John Lampe
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10829");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3723);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0876");
  script_name("scan for UPNP hosts");
  # this check was replaced by gb_upnp_detect.nasl (1.3.6.1.4.1.25623.1.0.103652)
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 by John Lampe");
  script_family("Windows");
  script_dependencies("global_settings.nasl");
  script_require_ports(5000);
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://grc.com/UnPnP/UnPnP.htm");

  script_tag(name:"summary", value:"Microsoft Universal Plug n Play is running on this machine. This service is dangerous for many
  different reasons.");

  script_tag(name:"solution", value:"To disable UPNP see the references.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # this check was replaced by gb_upnp_detect.nasl (1.3.6.1.4.1.25623.1.0.103652)

include('global_settings.inc');

if(islocalhost())exit(0);
if(TARGET_IS_IPV6())exit(0);

#script based on eeye advisory Multiple Remote Windows XP/ME/98 Vulnerabilities

  myaddr = this_host();
  dstaddr = get_host_ip();
  returnport = 80;

  mystring = string("NOTIFY * HTTP/1.1\r\n");
  mystring = mystring + string("HOST: ", "239.255.255.250" , ":1900\r\n");
  mystring = mystring + string("CACHE-CONTROL: max-age=10\r\n");
  mystring = mystring + string("LOCATION: http://" , myaddr, ":" , returnport , "/foo.xms\r\n");
  mystring = mystring + string("NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n");
  mystring = mystring + string("NTS: ssdp:alive\r\n");
  mystring = mystring + string("SERVER: OPENVAS/2001 UPnP/1.0 product/1.1\r\n");
  mystring = mystring + string("USN: uuid:OPENVAS\r\n\r\n");
  len = strlen(mystring);

  ippkt = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31337,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_UDP,
        ip_src  :myaddr
        );


  udppacket = forge_udp_packet(
        ip      :ippkt,
        uh_sport:1900,
        uh_dport:1900,
        uh_ulen :8 + len,
        data    :mystring
        );

  for(i=0;i<3;i++)
  {
  rpkt = send_packet(udppacket, pcap_active:FALSE);

  ippkt2 = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31338,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :myaddr
        );

  tcppacket = forge_tcp_packet(ip:ippkt2,
                               th_sport: 999,
                               th_dport: 1900,
                               th_flags:TH_RST,
                               th_seq: 3984,
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 0,
                               th_win: 8192,
                               th_urp: 0);

  filter = string("tcp and src " , dstaddr , " and dst port ", returnport);
  rpkt2 = send_packet(tcppacket, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
  if(rpkt2)
  {
  flags = get_tcp_element(tcp:rpkt2, element:"th_flags");

  if (flags & TH_SYN) {
       security_message(port:1900,protocol:"udp");
  }
  exit(0);
  }
  }

