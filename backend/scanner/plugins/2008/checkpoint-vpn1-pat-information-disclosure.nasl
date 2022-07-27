###############################################################################
# OpenVAS Vulnerability Test
# $Id: checkpoint-vpn1-pat-information-disclosure.nasl 10450 2018-07-07 09:48:13Z cfischer $
#
# Checkpoint VPN-1 PAT information disclosure
#
# Authors:
# Tim Brown <timb@openvas.org>
#
# Fixes (+note about FP): Vlatko Kosturjak <kost@linux.hr>
#
# Copyright:
# Copyright (c) 2008 Tim Brown and Portcullis Computer Security Ltd
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.80096");
  script_version("$Revision: 10450 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-07 11:48:13 +0200 (Sat, 07 Jul 2018) $");
  script_tag(name:"creation_date", value:"2008-11-05 16:59:22 +0100 (Wed, 05 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-5849");
  script_name("Checkpoint VPN-1 PAT information disclosure");
  script_category(ACT_GATHER_INFO);
  script_family("Firewalls");
  script_copyright("(c) Tim Brown and Portcullis Computer Security Ltd, 2008");
  script_dependencies("global_settings.nasl");
  script_require_ports(18264);
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.portcullis-security.com/293.php");

  script_tag(name:"solution", value:"We are not aware of a vendor approved solution at the current time.

  On the following platforms, we recommend you mitigate in the described manner:

  Checkpoint VPN-1 R55

  Checkpoint VPN-1 R65

  We recommend you mitigate in the following manner:

  Disable any implied rules and only open ports for required services
  Filter outbound ICMP time-to-live exceeded packets.");

  script_tag(name:"summary", value:"Checkpoint VPN-1 PAT information disclosure");

  script_tag(name:"insight", value:"By sending crafted packets to ports on the firewall which are mapped by port address translation (PAT)
  to ports on internal devices, information about the internal network may be disclosed in the resulting ICMP
  error packets. Port 18264/tcp on the firewall is typically configured in such a manner, with packets to this
  port being rewritten to reach the firewall management server. For example, the firewall fails to correctly
  sanitise the encapsulated IP headers in ICMP time-to-live exceeded packets resulting in internal IP addresses
  being disclosed.

  False positive:

  This could be false positive alert. Try running same scan against single host
  where this vulnerability is reported.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");

if(TARGET_IS_IPV6())exit(0);
if(islocalhost())exit(0);

port = 18264;
if (!get_port_state(port)){
  exit(0);
}

if (!soc = open_sock_tcp(port)){
  exit(0);
}

close(soc);

SCRIPT_DESC = "Checkpoint VPN-1 PAT information disclosure";

function packet_construct(_ip_src, _ip_ttl)
{
  _ip_id = rand() % 65535;
  _th_sport = (rand() % 64000) + 1024;
  _ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:_ip_id, ip_len:20, ip_off:0, ip_p:IPPROTO_TCP, ip_src:_ip_src, ip_ttl:_ip_ttl);
  _tcp = forge_tcp_packet(ip:_ip, th_sport:_th_sport, th_dport:18264, th_flags:TH_SYN, th_seq:_ip_ttl, th_ack:0, th_x2:0, th_off:5, th_win:2048, th_urp:0);
  return _tcp;
}

function packet_parse(_icmp, _ip_dst, _ttl)
{
  _ip = get_icmp_element(icmp:_icmp, element:"data");
  _ip_p = get_ip_element(ip:_ip, element:"ip_p");
  _ip_dst2 = get_ip_element(ip:_ip, element:"ip_dst");
  _ip_hl = get_ip_element(ip:_ip, element:"ip_hl");
  _tcp = substr(_ip, (_ip_hl * 4), strlen(_ip));
  _ih_dport = (ord(_tcp[2]) * 256) + ord(_tcp[3]);
  _data = "";
  if ((_ip_p == IPPROTO_TCP) && (_ip_dst2 != _ip_dst) && (_ih_dport == 18264))
  {
    _data = "Internal IP disclosed: " + _ip_dst2 + " (ttl: " +_ttl + ')\n';
    set_kb_item(name:"Checkpoint/Manager/ipaddress", value:_ip_dst2);
    register_host_detail(name:"App", value:"cpe:/a:checkpoint:vpn-1", desc:SCRIPT_DESC);
  }
  return _data;
}

sourceipaddress = this_host();
destinationipaddress = get_host_ip();
packetfilter = "dst host " + sourceipaddress + " and icmp and (icmp[0]=11)";
reportout = "";
for (ttl = 1; ttl <= 50; ttl ++)
{
  requestpacket = packet_construct(_ip_src:sourceipaddress, _ip_ttl:ttl);
  responsepacket = send_packet(requestpacket, pcap_active:TRUE, pcap_filter:packetfilter, pcap_timeout:1);
  if (responsepacket)
  {
    reportdata = packet_parse(_icmp:responsepacket, _ip_dst:destinationipaddress, _ttl:ttl);
    reportout = reportout + reportdata;
  }
}

if (reportout != "") {
  reportheading = "Disclosures:";
  wholereport = reportheading + reportout;
  security_message(protocol:"tcp", port:port, data:wholereport);
}
