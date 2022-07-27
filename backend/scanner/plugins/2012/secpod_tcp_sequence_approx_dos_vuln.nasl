###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tcp_sequence_approx_dos_vuln.nasl 11066 2018-08-21 10:57:20Z asteins $
#
# TCP Sequence Number Approximation Reset Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.902815");
  script_bugtraq_id(10183);
  script_version("$Revision: 11066 $");
  script_cve_id("CVE-2004-0230");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-08-21 12:57:20 +0200 (Tue, 21 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-03-01 15:15:15 +0530 (Thu, 01 Mar 2012)");
  script_name("TCP Sequence Number Approximation Reset Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_open_tcp_ports.nasl", "global_settings.nasl");
  script_mandatory_keys("TCP/PORTS");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/15886");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA04-111A.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IY55949");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IY55950");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=isg1IY62006");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS05-019.mspx");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms06-064.mspx");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20040420-tcp-nonios.html");
  script_xref(name:"URL", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20040420-tcp-nonios.html");

  script_tag(name:"summary", value:"The host is running TCP services and is prone to denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"A TCP Reset packet with a different sequence number is sent to
  the target. A previously open connection is then checked to see if the target closed it or not.");

  script_tag(name:"solution", value:"Please see the referenced advisories for more information on obtaining
  and applying fixes.");

  script_tag(name:"insight", value:"The flaw is triggered when spoofed TCP Reset packets are received by the
  targeted TCP stack and will result in loss of availability for the attacked TCP services.");

  script_tag(name:"affected", value:"TCP/IP v4");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to guess sequence numbers
  and cause a denial of service to persistent TCP connections by repeatedly injecting a TCP RST packet.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("misc_func.inc");

if(TARGET_IS_IPV6()){
  exit(0);
}

if(islocalhost()){
 exit(0);
}

port = get_host_open_tcp_port();

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

srcport = get_source_port(soc);
if(!srcport){
  exit(0);
}

dstip = get_host_ip();
srcip = this_host();

## Filter for Packets
filter = string("tcp and src ", dstip, " and dst ", srcip, " and dst port ",
                srcport, " and src port ", port);

## Send a character and receive the response
res = send_capture(socket:soc, data:"X", pcap_filter:filter);

if(!res){
  exit(0);
}

tcp_seq = get_tcp_element(tcp:res, element:"th_ack");
flags = get_tcp_element(tcp:res, element:"th_flags");

if(!tcp_seq || (flags & TH_FIN) || (flags & TH_RST)) {
  exit(0);
}

## Spoof a TCP RST packet by incrementing sequence number
ip = forge_ip_packet( ip_v   : 4,
                      ip_hl  : 5,
                      ip_tos : 0,
                      ip_len : 20,
                      ip_id  : rand(),
                      ip_p   : IPPROTO_TCP,
                      ip_ttl : 255,
                      ip_off : 0,
                      ip_src : srcip );

## Increment sequence number by 1024
tcp = forge_tcp_packet( ip       : ip,
                        th_ack   : 0,
                        th_dport : port,
                        th_flags : TH_RST,
                        th_seq   : tcp_seq + 1024,
                        th_sport : srcport,
                        th_x2    : 0,
                        th_off   : 5,
                        th_win   : 1024,
                        th_urp   : 0);


## Send the spoofed RST packet
send_packet(tcp, pcap_active:FALSE);

## Send a character and receive the response
res = send_capture(socket:soc, data:"X", pcap_filter:filter);
if(res)
{
  flags = get_tcp_element(tcp:res, element:"th_flags");

  if (flags & TH_RST){
    security_message(port:0);
  }
}
