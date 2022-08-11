###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_router_synful_knock_vuln.nasl 11452 2018-09-18 11:24:16Z mmartin $
#
# Cisco Router SYNful Knock Vulnerability
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805740");
  script_version("$Revision: 11452 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 13:24:16 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-09-23 12:30:00 +0530 (Wed, 23 Sep 2015)");
  script_name("Cisco Router SYNful Knock Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www2.fireeye.com/rs/848-DID-242/images/rpt-synful-knock.pdf");
  script_xref(name:"URL", value:"http://www.zdnet.com/article/synful-knock-cisco-router-malware-in-the-wild");
  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis.html");

  script_tag(name:"summary", value:"This host has Cisco router
  and is prone to SYNful Knock vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted tcp packet request and
  check whether it is able to obtain valuable information or not");

  script_tag(name:"insight", value:"The flaw is due to cisco router firmware
  allowing remote attacker to change the memory values.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain control of an affected device and compromise its integrity
  with a modified Cisco IOS software image.");

  script_tag(name:"affected", value:"Cisco 1841
  Cisco 2811
  Cisco 3825");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");

dport = get_http_port(default:80);

ttl = 64;
saddr = this_host();
daddr = get_host_ip();
sport = rand() % (65536 - 1024) + 1024;

ip = forge_ip_packet(
     ip_hl    : 5,
     ip_v     : 4,
     ip_tos   : 0,
     ip_len   : 65535,
     ip_id    : 0x7f35,
     ip_off   : 0,
     ip_ttl   : 64,
     ip_p     : 6,
     ip_src   : saddr,
     ip_dst   : daddr);

tcppacket = forge_tcp_packet(
            ip : ip,
            th_sport : sport,
            th_dport : dport,
            th_flags : 0x02,
            th_seq   : 0,
            th_ack   : 0,
            th_off   : 5,
            th_win   : 1480,
            th_urp   : 0);

if(tcppacket && hexstr(tcppacket) =~ "020405b40101040201030305")
{
  security_message(port:dport);
  exit(0);
}

exit(99);
