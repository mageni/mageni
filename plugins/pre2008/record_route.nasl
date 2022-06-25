###############################################################################
# OpenVAS Vulnerability Test
# $Id: record_route.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# Record route
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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

# References:
# RFC 792 Internet Control Message Protocol
# RFC 791 Internet Protocol

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12264");
  script_version("$Revision: 10411 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Record route");
  # See bugtraq ID # 10653
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Michel Arboi");
  script_family("General");
  script_dependencies("global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"This plugin sends packets with the 'Record Route' option.
  It is a complement to traceroute.");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");

if(TARGET_IS_IPV6())exit(0);
if (islocalhost()) exit(0); # Don't test the loopback interface

srcaddr = this_host();
dstaddr = get_host_ip();
n = 3;	# Number of tries

function report(packet, proto)
{
 local_var	rep, ihl, p, i, j, route;

 if ( ! packet ) return 0;

 rep = strcat('Here is the route recorded between ', srcaddr,
	' and ', dstaddr, ' :\n');

 ihl = (ord(packet[0]) & 0xF) * 4;
 ##display("IHL=", ihl, "\n");
 # No need to associate this piece of information with a specific port
 ##dump(ddata: packet, dtitle: "packet");
 p = ord(packet[22]) + 20;
 if (p > ihl) p = ihl;
 for (i = 24; i < p; i += 4)
 {
  for (j = -1; j < 3; j ++)
   route = strcat(route, ord(packet[i+j]), '.');
  route = strcat(route, '\n');
 }
 if ( strlen(route) > 4 )
 log_message(port: 0, protocol: proto, data: rep + route);
}

# Currently, insert_ip_options() is buggy
rr = raw_string(	7,	# RR
			3+36,	# Length
			4,	# Pointer
			0)	# Padding
 + crap(length: 36, data: raw_string(0));


# We cannot use icmp_seq to identifies the datagrams because
# forge_icmp_packet() is buggy. So we use the data instead

filter = strcat("icmp and icmp[0]=0 and src ", dstaddr, " and dst ", srcaddr);

d = rand_str(length: 8);
for (i = 0; i < 8; i ++)
  filter = strcat(filter, " and icmp[", i+8, "]=", ord(d[i]));

ip = forge_ip_packet(ip_hl: 15, ip_v: 4, ip_tos: 0, ip_id: rand() % 65536,
	ip_off: 0, ip_ttl : 0x40, ip_p: IPPROTO_ICMP, ip_src : srcaddr,
	data: rr, ip_len: 38+36);
icmp = forge_icmp_packet(ip: ip, icmp_type:8, icmp_code:0, icmp_seq: 0,
	icmp_id: rand() % 65536, data: d);
r = NULL;
for (i = 0; i < n && ! r; i ++)
  r = send_packet(icmp, pcap_active: TRUE, pcap_filter: filter);
if (i < n) report(packet: r, proto: "icmp");
