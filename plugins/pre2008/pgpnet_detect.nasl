###############################################################################
# OpenVAS Vulnerability Test
# $Id: pgpnet_detect.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# Detect presence of PGPNet server and its version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10175");
  script_version("$Revision: 10411 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Detect presence of PGPNet server and its version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("global_settings.nasl");
  script_require_udp_ports(500);
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Block those ports from outside communication");

  script_tag(name:"summary", value:"It is possible to detect the existing of PGPNet, by connecting to its
  open UDP port (500) and sending it a session init packet, the PGPNet daemon
  would respond (making it possible to know that PGPNet is installed on the
  computer) with the version of the OpenPGP package it uses.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(TARGET_IS_IPV6())exit(0);
if(islocalhost())exit(0);

srcaddr = this_host();
dstaddr = get_host_ip();

magic_num = rand();

r1 = rand() % 255;
r2 = rand() % 255;

raw_data = raw_string(
r1,    r2,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x0D, 0x00, 0x00, 0x5C, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x01, 0x01, 0x00,
0x02, 0x03, 0x00, 0x00, 0x24, 0x01, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x06,
0x80, 0x02, 0x00, 0x02, 0x80, 0x03, 0x00, 0x03, 0x80, 0x04, 0x00, 0x05, 0x80,
0x0B, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x04, 0x00, 0x01, 0x51, 0x80, 0x00, 0x00,
0x00, 0x24, 0x02, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x05, 0x80, 0x02, 0x00,
0x01, 0x80, 0x03, 0x00, 0x03, 0x80, 0x04, 0x00, 0x02, 0x80, 0x0B, 0x00, 0x01,
0x00, 0x0C, 0x00, 0x04, 0x00, 0x01, 0x51, 0x80, 0x00, 0x00, 0x00, 0x10);
raw_data = raw_data + "OpenPGPdetect";

IPH = 20;
UDPH = 8;
PGPNET_BASE = 137;
UDP_LEN = UDPH + PGPNET_BASE;
IP_LEN = IPH + UDP_LEN;

ip = forge_ip_packet(ip_v : 4,
					 ip_hl : 5,
					 ip_tos : 0,
					 ip_len : IP_LEN,
					 ip_id : 0xABBA,
					 ip_p : IPPROTO_UDP,
					 ip_ttl : 255,
					 ip_off : 0,
					 ip_src : srcaddr,
					 ip_dst : dstaddr);

dstport = 500;
srcport = 500;
if( ! get_udp_port_state( dstport ) ) exit(0);

udpip = forge_udp_packet(ip : ip,
						 uh_sport : srcport,
						 uh_dport : dstport,
						 uh_ulen : UDP_LEN, #udp = 8
						 data : raw_data);

filter = string("((udp and dst port ", srcport, ") or (icmp)) and src host ", dstaddr, " and dst host ", srcaddr);
result_suc = send_packet(udpip, pcap_active:TRUE, pcap_filter:filter);
if (result_suc)
{
 protocol_type = get_ip_element(ip:result_suc, element:"ip_p");
 if (protocol_type == IPPROTO_UDP)
 {
  result = get_udp_element(udp:result_suc, element:"data");
  if(strlen(result) < 88) exit(0);
  if ((result[2] == raw_string(0x00)) && (result[3] == raw_string(0x00)) &&
      (result[4] == raw_string(0x00)) && (result[5] == raw_string(0x00)) &&
	  (result[6] == raw_string(0x00)) && (result[7] == raw_string(0x00)))
   {
    if (
	    (result[16] == raw_string(0x01)) && (result[17] == raw_string(0x10)) &&
        (result[18] == raw_string(0x02)))
        {
	     OpenPGP = "";
	     for (i = 0; i < 1000; i = i + 1)
	     {
	      if (result[88+i] == raw_string(0x00))
          {
           i = 1000;
          }
          else
          {
           OpenPGP = OpenPGP + result[88+i];
          }
		 }
		 if (i == 1000)
		 {
		  warning_text = "PGPNet uses OpenPGP build version: ";
		  warning_text = warning_text + OpenPGP;
                  log_message(port:500, data: warning_text);
		 }
        }
   }
 }
}
